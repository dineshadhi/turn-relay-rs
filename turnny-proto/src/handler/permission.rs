use crate::{
    error::ProtoError,
    events::{SessionClose, TurnEvent},
    is_attrs,
    node::TurnNode,
    wire::{
        attribute::{AttributeTrait, ErrorCodeAttr, MessageIntegAttr, NonceAttr, RealmAttr, UsernameAttr, XorPeerAttr},
        error::TurnErrorCode,
        message::TurnMessage,
        method::{MKind, Method},
    },
};
use std::net::SocketAddr;
use tracing::instrument;

pub(crate) struct Permission;

impl Permission {
    #[instrument("Permission::reject", skip_all)]
    pub fn reject(node: &mut TurnNode, code: TurnErrorCode, req: TurnMessage) {
        tracing::error!(?code, "Create Permission Failed");

        let mut res = req.extend(Method::Permission(MKind::Error));
        res.set_attr::<ErrorCodeAttr>(code.clone());
        res.set_attr::<RealmAttr>(node.realm.clone());
        res.set_attr::<NonceAttr>(node.get_nonce_string().to_owned());

        node.add_event(TurnEvent::SendToClient(res.into()));
    }

    #[instrument("Permission::success", skip_all)]
    fn success(node: &mut TurnNode, req: TurnMessage, _peer_addr: SocketAddr) -> Result<(), ProtoError> {
        let peer_addr = req.get_attr::<XorPeerAttr>()?;
        node.add_peer(peer_addr);

        let mut res = req.extend(Method::Permission(MKind::Success));
        res.set_attr::<MessageIntegAttr>(res.compute_integrity()?);
        node.add_event(TurnEvent::SendToClient(res.into()));

        tracing::info!(?_peer_addr, "Permission Success");

        Ok(())
    }

    pub fn process(node: &mut TurnNode, req: TurnMessage) -> Result<(), ProtoError> {
        if let Err(e) = is_attrs!(req, MessageIntegAttr, NonceAttr, XorPeerAttr, RealmAttr, UsernameAttr,) {
            tracing::error!("{:?} Missing", e);
            Self::reject(node, TurnErrorCode::BadRequest, req);
            return Ok(());
        }

        let nonce = req.get_attr::<NonceAttr>()?;
        let peer_addr = req.get_attr::<XorPeerAttr>()?;

        match () {
            _ if !node.has_valid_lifetime() => {
                Self::reject(node, TurnErrorCode::BadRequest, req);
                node.add_event(TurnEvent::Close(SessionClose::LifetimeExpired))
            }
            _ if node.get_nonce_string() != &nonce => Self::reject(node, TurnErrorCode::StaleNonce, req),
            _ if !req.is_authenticated() => node.authenticate(req)?,
            _ if !node.is_permission_issued(&peer_addr) => {
                tracing::info!(?peer_addr, "TurnEvent:NeedsPermission");
                node.add_event(TurnEvent::NeedsPermission(req));
            }
            _ => return Self::success(node, req, peer_addr),
        }

        Ok(())
    }
}
