use crate::{
    error::ProtoError,
    events::{SessionClose, TurnEvent},
    is_attrs,
    node::TurnNode,
    wire::{
        attribute::{AttributeTrait, ChannelNumberAttr, ErrorCodeAttr, MessageIntegAttr, NonceAttr, RealmAttr, XorPeerAttr},
        error::TurnErrorCode,
        message::TurnMessage,
        method::{MKind, Method},
    },
};
use std::net::SocketAddr;
use tracing::instrument;

pub(crate) struct ChannelBind;

impl ChannelBind {
    #[instrument("ChannelBind::reject", skip_all)]
    pub fn reject(node: &mut TurnNode, code: TurnErrorCode, req: TurnMessage) {
        let mut res = req.extend(Method::ChannelBind(MKind::Error));
        res.set_attr::<ErrorCodeAttr>(code.clone());
        res.set_attr::<RealmAttr>(node.realm.clone());
        res.set_attr::<NonceAttr>(node.get_nonce_string().to_owned());

        tracing::error!(?code, "Channel Bind Failed");

        node.add_event(TurnEvent::SendToClient(res.into()));
    }

    #[instrument("ChannelBind::success", skip_all)]
    pub fn success(node: &mut TurnNode, req: TurnMessage, peer_addr: SocketAddr, channel: u16) -> Result<(), ProtoError> {
        node.bind_channel(peer_addr, channel);

        let mut res = req.extend(Method::ChannelBind(MKind::Success));
        res.set_attr::<MessageIntegAttr>(res.compute_integrity()?);
        node.add_event(TurnEvent::SendToClient(res.into()));

        tracing::info!(?peer_addr, channel = format!("0x{:x}", channel), "Channel Bind Success");

        Ok(())
    }

    pub fn process(node: &mut TurnNode, req: TurnMessage) -> Result<(), ProtoError> {
        if let Err(e) = is_attrs!(req, ChannelNumberAttr, XorPeerAttr, RealmAttr, NonceAttr, MessageIntegAttr,) {
            tracing::error!("Bad Request - Missing Attrs {:?}", e);
            Self::reject(node, TurnErrorCode::BadRequest, req);
            return Ok(());
        }

        let nonce = req.get_attr::<NonceAttr>()?;
        let peer_addr = req.get_attr::<XorPeerAttr>()?;
        let channel = req.get_attr::<ChannelNumberAttr>()?;

        match () {
            _ if !node.has_valid_lifetime() => {
                Self::reject(node, TurnErrorCode::BadRequest, req);
                node.add_event(TurnEvent::Close(SessionClose::LifetimeExpired))
            }
            _ if node.get_nonce_string() != &nonce => {
                tracing::error!("Nonce Mismatch - {} {}", node.get_nonce_string(), nonce);
                Self::reject(node, TurnErrorCode::StaleNonce, req);
            }
            _ if !req.is_authenticated() => node.authenticate(req)?,
            _ if !node.is_peer(&peer_addr) => Self::reject(node, TurnErrorCode::BadRequest, req),
            _ => return Self::success(node, req, peer_addr, channel),
        }

        Ok(())
    }
}
