use super::error::ProtoError;
use crate::{
    coding::Decode,
    config::ProtoConfig,
    events::{InputEvent, TurnEvent},
    handler::{Handler, allocate::Allocate, permission::Permission},
    wire::{
        Nonce,
        attribute::XorPeerAttr,
        error::TurnErrorCode,
        message::{StunMessage, TurnMessage},
        method::{MKind, Method},
    },
};
use bytes::{Buf, BytesMut};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    task::Poll,
    time::Instant,
};

#[macro_export]
macro_rules! is_expired {
    ($earlier:expr, $time:expr) => {
        Instant::now().duration_since($earlier).as_secs() >= $time
    };
}

// TURN State Machine
#[derive(Debug)]
pub struct TurnNode {
    // Remote client address
    pub(crate) remote: SocketAddr,
    // Realm set by the app
    pub(crate) realm: String,
    // Config set by the app
    pub(crate) config: Arc<ProtoConfig>,
    // Address that was allocated to this node.
    relay_addr: Option<SocketAddr>,
    // Entry of other Peer Adress / ChannelBinds after successful permission request
    peers: HashMap<(SocketAddr, Option<u16>), Instant>,
    // List of peers approved by the app to be added to the peers list now and in the future.
    permitted_peers: Vec<SocketAddr>,
    // Liftime of this session obtained from Allocate request. Periodically refreshed via Refresh request.
    lifetime: (u64, Instant),
    // Password assigned this node by the app. Cached when the first TurnEvent::NeedsAuth Request is sent.
    password: Option<String>,
    buffer: BytesMut,
    nonce: Nonce,
    event_queue: VecDeque<TurnEvent>,
}

impl TurnNode {
    pub fn new(remote: SocketAddr, config: Arc<ProtoConfig>) -> Self {
        Self {
            buffer: Default::default(),
            remote,
            permitted_peers: Default::default(),
            relay_addr: None,
            nonce: Nonce::default(),
            realm: config.realm.clone(),
            event_queue: Default::default(),
            peers: HashMap::default(),
            password: None,
            lifetime: (0, Instant::now()),
            config,
        }
    }
}

impl TurnNode {
    fn decode_stunmsg(&mut self) -> Result<StunMessage, ProtoError> {
        let mut cursor = std::io::Cursor::new(&mut self.buffer);
        let msg = StunMessage::decode(&mut cursor)?;
        let processed = cursor.position() as usize;
        self.buffer.advance(processed);
        Ok(msg)
    }

    pub(crate) fn add_event(&mut self, event: TurnEvent) {
        self.event_queue.push_back(event);
    }

    pub(crate) fn add_peer(&mut self, peer_addr: SocketAddr) {
        self.peers.insert((peer_addr, None), Instant::now());
    }

    pub(crate) fn is_peer(&mut self, peer_addr: &SocketAddr) -> bool {
        // If the peer_addr is in trusted turn list, permission will be eventually granted upon request, so we consider it as granted by default.
        // NOTE : Chrome sends send indications right away after the Permission rquest before we grant permissions.
        // The state machine will take two cycles to grant permission (Refer NeedsAuth Event).
        // This trusted_ip_list ensures that there is no dropping of Send Indications.
        let is_trusted = self.is_trusted_peer(peer_addr);
        let is_peer = self
            .peers
            .iter()
            .any(|((addr, _), at)| addr == peer_addr && !is_expired!(*at, self.config.permission_max_time));

        is_trusted || is_peer
    }

    pub(crate) fn is_trusted_peer(&self, peer_addr: &SocketAddr) -> bool {
        self.config.trusted_turn_ips.contains(&peer_addr.ip())
    }

    pub(crate) fn bind_channel(&mut self, peer_addr: SocketAddr, channel: u16) {
        self.peers.insert((peer_addr, Some(channel)), Instant::now());
    }

    pub(crate) fn get_bound_peer_addr(&self, channel: &u16) -> Option<SocketAddr> {
        self.peers.iter().find_map(|((addr, ch), at)| match ch {
            Some(ch) => match channel == ch && !is_expired!(*at, self.config.permission_max_time) {
                true => Some(addr.to_owned()),
                false => None,
            },
            _ => None,
        })
    }

    pub(crate) fn get_bound_channel(&self, peer_addr: &SocketAddr) -> Option<u16> {
        self.peers.iter().find_map(
            |((addr, ch), at)| match addr == peer_addr && !is_expired!(*at, self.config.permission_max_time) {
                true => ch.to_owned(),
                false => None,
            },
        )
    }

    pub(crate) fn get_nonce_string(&mut self) -> &String {
        self.nonce.get(self.config.nonce_max_time)
    }

    pub(crate) fn set_lifetime(&mut self, secs: u64) {
        self.lifetime = (secs, Instant::now());
    }

    pub(crate) fn set_relay_addr(&mut self, addr: SocketAddr) {
        self.relay_addr = Some(addr)
    }

    pub(crate) fn get_relay_addr(&self) -> Option<SocketAddr> {
        self.relay_addr
    }

    pub(crate) fn has_valid_lifetime(&self) -> bool {
        let (timelimit, at) = self.lifetime;
        self.relay_addr.is_some() && !is_expired!(at, timelimit)
    }

    // authenticates using the cached password, if not, adds NeedsAuth event
    pub(crate) fn authenticate(&mut self, mut msg: TurnMessage) -> Result<(), ProtoError> {
        // Check if password is cached and authenticate
        match &self.password {
            Some(password) => match msg.authenticate(password) {
                Ok(_) => {
                    tracing::info!("Auth Success");
                    Handler::handle_turn_msg(self, msg) // Process the req again, if auth is a succcess.
                }
                Err(_) => Handler::reject_msg(self, msg, TurnErrorCode::WrongCredentials), // Otherwise reject it
            },
            None => {
                tracing::info!("TurnEvent::NeedsAuth");
                self.add_event(TurnEvent::NeedsAuth(msg)); // Send NeedsAuth, if there is no cache
                Ok(())
            }
        }
    }

    /// This method is used to drive the State Machine
    pub fn drive_forward<B: Buf>(&mut self, event: InputEvent<B>) -> Result<(), ProtoError> {
        match event {
            InputEvent::NetworkBytes(data) => {
                self.buffer.extend_from_slice(data.chunk());
                while self.buffer.has_remaining() {
                    let msg = self.decode_stunmsg()?;
                    Handler::handle_stun_msg(self, msg)?;
                }
                Ok(())
            }
            InputEvent::DataFromPeer(peer_addr, data) => Handler::handle_data_from_peer(self, peer_addr, data),
        }
    }

    /// This method should be called to ask the State Machine about next steps.
    pub fn poll(&mut self) -> Poll<TurnEvent> {
        match self.event_queue.pop_front() {
            Some(msg) => Poll::Ready(msg),
            None => Poll::Pending,
        }
    }

    pub fn auth_msg(&mut self, mut msg: TurnMessage, password: &str) -> Result<(), ProtoError> {
        let _e = msg.span.clone().entered();
        match msg.authenticate(password) {
            Ok(_) => {
                tracing::info!("auth_msg : Authenticated Succesfully");
                self.password = Some(password.to_string()); // Cache the password
                Handler::handle_turn_msg(self, msg)
            }
            Err(_) => Handler::reject_msg(self, msg, TurnErrorCode::WrongCredentials),
        }
    }

    pub fn reject_request(&mut self, msg: TurnMessage, errcode: TurnErrorCode) -> Result<(), ProtoError> {
        let _e = msg.span.clone().entered();
        Handler::reject_msg(self, msg, errcode)
    }

    pub fn alloc_addr(&mut self, relay_addr: SocketAddr, msg: TurnMessage) -> Result<(), ProtoError> {
        let _e = msg.span.clone().entered();
        tracing::info!(?relay_addr, "Address Allocated");
        match matches!(msg.method, Method::Allocate(MKind::Request)) {
            true => Allocate::process(self, msg, Some(relay_addr))?,
            false => tracing::error!("alloc_addr : Invalid TurnMessage Passed {:?}", msg.method),
        }
        Ok(())
    }

    pub fn issue_permission(&mut self, msg: TurnMessage) -> Result<(), ProtoError> {
        let _e = msg.span.clone().entered();
        match matches!(msg.method, Method::Permission(MKind::Request)) {
            true => {
                let peer_addr = msg.get_attr::<XorPeerAttr>()?;
                self.permitted_peers.push(peer_addr);
                Permission::process(self, msg)?
            }
            false => tracing::error!("issue_permission : Invalid TurnMessage Passed {:?}", msg.method),
        }
        Ok(())
    }

    // If the IPaddr is same as the host, the permission is granted automatically. See `trusted_turn_ips` always have the host in the list. It can be configured to add other TURN nodes as trusted.
    // Once the ips are added as trusted, no Permission Request (TurnEvent::NeedsPermission) will be sent to the app. SendIndications will be processed without explicit permission from the app.
    // If the IPaddr is foreign, a proper request must be sent to the app.
    pub(crate) fn is_permission_issued(&self, peer_addr: &SocketAddr) -> bool {
        self.is_trusted_peer(peer_addr) || self.permitted_peers.contains(peer_addr)
    }

    pub fn set_realm(&mut self, realm: String) {
        self.realm = realm;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;
    use std::sync::Arc;

    const ALLOCATE_DUMP: &str = "000300882112a442415a4e555631705551464b77001900041100000000060044323a43543a313732393335383235323738303a3230303a39306438363634382d666637322d346162332d313732393335383235323737382d316335346333336264333565001400077274632e636f6d0000150010525256305859375847355462745a6c48000800143bb6ff776c115a45b2a8d9c378621ecd3c1cca62";

    #[test]
    fn sm_drive_test() {
        let allocate = hex::decode(ALLOCATE_DUMP).unwrap();
        let mut sm = TurnNode::new("0.0.0.0:0".parse().unwrap(), Arc::new(ProtoConfig::default().unwrap()));
        // Pushing partial data. Must return NeedMoreData
        assert_eq!(
            sm.drive_forward(InputEvent::NetworkBytes(Bytes::copy_from_slice(&allocate[..20])))
                .unwrap_err(),
            ProtoError::NeedMoreData
        );
        sm.drive_forward(InputEvent::NetworkBytes(Bytes::copy_from_slice(&allocate[20..])))
            .unwrap()
    }
}
