use crate::{
    endpoint::EndpointStream,
    instance::{TurnInstance, TurnService},
    portallocator::PortAllocator,
    session_counter,
};
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::future::poll_fn;
use opentelemetry::{KeyValue, global};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::{Span, instrument};
use turn_proto::{
    coding::Encode,
    error::ProtoError,
    events::{
        InputEvent::{self, NetworkBytes},
        TurnEvent,
    },
    node::TurnNode,
    wire::{
        attribute::{UsernameAttr, XorPeerAttr},
        message::TurnMessage,
    },
};

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    UDP,
    TCP,
}

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct SessionID {
    pub(crate) remote: SocketAddr,
    pub(crate) local: SocketAddr,
    pub(crate) protocol: Protocol,
}

#[derive(Debug)]
pub struct TurnSession<S: TurnService, P: PortAllocator> {
    pub sid: SessionID,
    relay_addr: Option<SocketAddr>,
    username: Option<String>,
    stream: EndpointStream,
    instance: Arc<TurnInstance<S, P>>,
    // Unbounded sender that is distributed to peers to send the data relayed from the client
    send: UnboundedSender<InputEvent<Bytes>>,
    // Unbounded receiver to receive the data sent via `send` and process it to be sent to the client.
    recv: UnboundedReceiver<InputEvent<Bytes>>,
    // It is expensive to look up Senders globally each time, this is a cache to store it locally.
    peers_sender_cache: DashMap<SocketAddr, UnboundedSender<InputEvent<Bytes>>>,
}

#[derive(Error, Debug)]
enum SessionState {
    #[error("Disconnected")]
    Disconnected,
    #[error("Idle Time out")]
    IdleTimeOut,
    #[error("Proto Error")]
    ProtoError(#[from] ProtoError),
    #[error("IO Error")]
    IOError(#[from] io::Error),
}

impl<S: TurnService, P: PortAllocator> TurnSession<S, P> {
    pub fn new(sid: SessionID, stream: EndpointStream, instance: Arc<TurnInstance<S, P>>) -> Self {
        let (send, recv) = mpsc::unbounded_channel::<InputEvent<Bytes>>();
        session_counter!(1, sid.protocol, sid.remote);
        Self {
            sid,
            stream,
            instance,
            send,
            recv,
            relay_addr: None,
            username: None,
            peers_sender_cache: Default::default(),
        }
    }

    fn process_incoming_data(&mut self, node: &mut TurnNode, data: Result<Option<Bytes>, io::Error>) -> Result<(), SessionState> {
        match data? {
            Some(data) => node.drive_forward(NetworkBytes(data)).map_err(|e| e.into()),
            None => Err(SessionState::Disconnected),
        }
    }

    #[instrument("Event::NeedsAuth", skip_all)]
    fn process_auth(&mut self, node: &mut TurnNode, req: TurnMessage) -> Result<(), SessionState> {
        let username = req.get_attr::<UsernameAttr>()?;
        match self.instance.service.get_password(&username) {
            Ok(password) => node.auth_msg(req, &password)?,
            Err(errcode) => node.reject_request(req, errcode)?,
        }
        Ok(())
    }

    #[instrument("Event::NeedsAllocation", skip_all)]
    fn process_alloc(&mut self, node: &mut TurnNode, req: TurnMessage, parent: Span) -> Result<(), SessionState> {
        let username = req.get_attr::<UsernameAttr>()?;
        let port = match self.instance.allocator.allocate_port(&username) {
            Ok(addr) => addr,
            Err(errcode) => return Ok(node.reject_request(req, errcode)?),
        };

        let alloc_addr: SocketAddr = format!("{}:{}", self.instance.config.server_addr_v4, port).parse().unwrap();

        self.relay_addr = Some(alloc_addr);
        self.username = Some(username.clone());

        parent.record("username", username);
        parent.record("relay_addr", alloc_addr.to_string());

        assert!(self.instance.relays.insert(alloc_addr, self.send.clone()).is_none());
        node.alloc_addr(alloc_addr, req)?;

        Ok(())
    }

    #[instrument("Event::NeedsPermission", skip_all)]
    fn process_permission(&mut self, node: &mut TurnNode, req: TurnMessage) -> Result<(), SessionState> {
        let peer_addr = req.get_attr::<XorPeerAttr>()?;
        match self.instance.service.check_permission(peer_addr) {
            Ok(_) => {
                tracing::info!(?peer_addr, "Permission Issued");
                node.issue_permission(req)?;
            }
            Err(errcode) => node.reject_request(req, errcode)?,
        }
        Ok(())
    }

    fn send_to_peer(&self, peer_addr: SocketAddr, data: Bytes) -> Result<(), SessionState> {
        let relay_addr = match self.relay_addr {
            Some(addr) => addr,
            None => {
                tracing::error!("send_to_peer failed. no address bound to current session");
                return Ok(());
            }
        };

        // Get the sender to relay the data to another session
        let sender = self.peers_sender_cache.get(&peer_addr).or_else(|| {
            if let Some(sender) = self.instance.relays.get(&peer_addr) {
                self.peers_sender_cache.insert(peer_addr, sender.clone()); // and cache it
                Some(sender)
            } else {
                tracing::error!("{:?} process_relay_data failed. no session bound to : {}", self.relay_addr, peer_addr);
                None
            }
        });

        if let Some(sender) = sender {
            if !sender.is_closed() {
                let event = InputEvent::DataFromPeer(relay_addr, data);
                if let Err(e) = sender.send(event) {
                    tracing::error!("process_relay_data failed. error dispatching to sender {e}");
                }
            } else {
                tracing::warn!("process_relay_data : sender closed");
            }
        }

        Ok(())
    }

    // #[instrument("process_event", skip(self, node, parent))]
    async fn process_event(&mut self, node: &mut TurnNode, event: TurnEvent, parent: Span) -> Result<(), SessionState> {
        match event {
            TurnEvent::SendToClient(resp) => self.stream.write(resp.bytes()?).await?,
            TurnEvent::NeedsAuth(req) => req.in_scope(|req| self.process_auth(node, req))?,
            TurnEvent::NeedsAllocation(req) => req.in_scope(|req| self.process_alloc(node, req, parent))?,
            TurnEvent::NeedsPermission(req) => req.in_scope(|req| self.process_permission(node, req))?,
            TurnEvent::SendToPeer(peer_addr, data) => self.send_to_peer(peer_addr, data)?,
            TurnEvent::Close(closetype) => {
                tracing::info!(?closetype, "TurnEvent::Close");
                return Err(SessionState::Disconnected)?;
            }
        }
        Ok(())
    }

    // Session Event Loop
    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut node = TurnNode::new(self.sid.remote, Arc::clone(&self.instance.proto_config));
        let timeout = Duration::from_secs(self.instance.config.session_idle_time);

        loop {
            let state = tokio::select! {
                read = self.stream.read_with_timeout(timeout) => match read {
                    Ok(data) => self.process_incoming_data(&mut node, data),
                    Err(_) => Err(SessionState::IdleTimeOut),
                },
                event = poll_fn(|_| node.poll()) => self.process_event(&mut node, event, Span::current()).await,
                event = self.recv.recv() => match event {
                    Some(InputEvent::DataFromPeer(addr, data)) => Ok(node.drive_forward(InputEvent::<Bytes>::DataFromPeer(addr, data))?),
                    _ => unreachable!(),
                }
            };

            if let Err(e) = state {
                match e {
                    SessionState::Disconnected => break,
                    SessionState::IdleTimeOut => break tracing::info!("Idle time out {}", self.instance.config.session_idle_time),
                    SessionState::ProtoError(ProtoError::NeedMoreData) => {} // TODO : Mark this as error for UDP. For TCP, its fine, because the stream is sometimes fragmented.
                    SessionState::ProtoError(perror) => tracing::error!("Proto Error - {:?}", perror),
                    SessionState::IOError(ioerror) => tracing::error!("IO Error - {:?}", ioerror),
                }
            }
        }

        if let (Some(username), Some(relay_addr)) = (self.username.as_ref(), self.relay_addr) {
            self.instance.allocator.surrender_port(username, relay_addr.port());
        }

        session_counter!(-1, self.sid.protocol, self.sid.remote);

        Ok(())
    }
}
