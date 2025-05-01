use tracing::{Level, event, instrument};

use crate::{
    error::ProtoError,
    events::TurnEvent::{NeedsAllocation, SendToClient},
    is_attrs,
    node::TurnNode,
    wire::{
        attribute::{AttributeTrait, ErrorCodeAttr, LifeTimeAttr, MessageIntegAttr, NonceAttr, RealmAttr, UsernameAttr, XorMappedAttr, XorRelayAttr},
        error::TurnErrorCode,
        message::TurnMessage,
        method::{MKind, Method},
    },
};
use std::net::SocketAddr;

#[derive(Debug)]
pub(crate) struct Allocate;

impl Allocate {
    pub fn reject(node: &mut TurnNode, code: TurnErrorCode, req: TurnMessage) {
        let mut res = req.extend(Method::Allocate(MKind::Error));
        res.set_attr::<ErrorCodeAttr>(code.clone());
        res.set_attr::<RealmAttr>(node.realm.clone());
        res.set_attr::<NonceAttr>(node.get_nonce_string().to_owned());
        node.add_event(SendToClient(res.into()));
        event!(Level::INFO, ?code, "Allocate Failed Rejected");
    }

    pub fn success(node: &mut TurnNode, relay_addr: SocketAddr, req: TurnMessage, lifetime: u32) -> Result<(), ProtoError> {
        let mut res = req.extend(Method::Allocate(MKind::Success));
        res.set_attr::<XorRelayAttr>(relay_addr);
        res.set_attr::<XorMappedAttr>(node.remote);
        res.set_attr::<RealmAttr>(node.realm.clone());
        res.set_attr::<LifeTimeAttr>(lifetime);
        res.set_attr::<MessageIntegAttr>(res.compute_integrity()?);

        node.set_relay_addr(relay_addr);
        node.set_lifetime(lifetime as u64);

        node.add_event(SendToClient(res.into()));
        tracing::info!(relay_addr=?relay_addr, lifetime=?lifetime, "Allocation successful");
        Ok(())
    }

    pub fn process(node: &mut TurnNode, req: TurnMessage, relay_addr: Option<SocketAddr>) -> Result<(), ProtoError> {
        if let Err(_) = is_attrs!(req, UsernameAttr, RealmAttr, NonceAttr,) {
            Self::reject(node, TurnErrorCode::Unauthorized, req);
            return Ok(());
        }

        tracing::info!("Alloc Resquest : {:?}", req.attrs);

        let nonce = req.get_attr::<NonceAttr>()?;
        let lifetime = req.get_attr::<LifeTimeAttr>().unwrap_or_else(|_| node.config.max_alloc_time);

        // NOTE : Order of evaluation is important. Only one arm is selected.
        match () {
            _ if node.get_relay_addr().is_some() => return Ok(()), // TODO : Treat as implicit success/refreAsh
            _ if node.get_nonce_string() != &nonce => Self::reject(node, TurnErrorCode::StaleNonce, req),
            _ if !req.is_authenticated() => node.authenticate(req)?,
            _ if relay_addr.is_none() => {
                tracing::info!("Needs Allocation Requested");
                node.add_event(NeedsAllocation(req))
            }
            _ => return Self::success(node, relay_addr.unwrap(), req, lifetime),
        }

        Ok(())
    }
}
