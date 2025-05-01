use crate::{
    error::ProtoError,
    events::{
        SessionClose,
        TurnEvent::{self},
    },
    is_attrs,
    node::TurnNode,
    wire::{
        attribute::{AttributeTrait, ErrorCodeAttr, LifeTimeAttr, MessageIntegAttr, NonceAttr, RealmAttr},
        error::TurnErrorCode,
        message::TurnMessage,
        method::{MKind, Method},
    },
};

pub(crate) struct Refresh;

impl Refresh {
    pub fn reject(node: &mut TurnNode, code: TurnErrorCode, req: TurnMessage) {
        tracing::debug!(?code, "Rejecting refresh request");
        let mut res = req.extend(Method::Refresh(MKind::Error));
        res.set_attr::<ErrorCodeAttr>(code);
        res.set_attr::<RealmAttr>(node.realm.clone());
        res.set_attr::<NonceAttr>(node.get_nonce_string().to_owned());

        node.add_event(TurnEvent::SendToClient(res.into()));
    }

    pub fn success(node: &mut TurnNode, lifetime: u32, req: TurnMessage) -> Result<(), ProtoError> {
        tracing::info!(lifetime=?lifetime, "Refresh success");
        let mut res = req.extend(Method::Refresh(MKind::Success));
        res.set_attr::<LifeTimeAttr>(lifetime);
        res.set_attr::<MessageIntegAttr>(res.compute_integrity()?);

        node.set_lifetime(lifetime as u64);
        node.add_event(TurnEvent::SendToClient(res.into()));

        Ok(())
    }

    pub fn process(node: &mut TurnNode, req: TurnMessage) -> Result<(), ProtoError> {
        if let Err(e) = is_attrs!(req, RealmAttr, MessageIntegAttr, NonceAttr,) {
            tracing::error!("Bad Request - Missing Attrs {:?}", e);
            Self::reject(node, TurnErrorCode::Unauthorized, req);
            return Ok(());
        }

        let lifetime = req.get_attr::<LifeTimeAttr>().unwrap_or(node.config.max_alloc_time);
        let nonce = req.get_attr::<NonceAttr>()?;

        match () {
            _ if !node.has_valid_lifetime() => {
                Self::reject(node, TurnErrorCode::BadRequest, req);
                node.add_event(TurnEvent::Close(SessionClose::LifetimeExpired));
            }
            _ if node.get_nonce_string() != &nonce => Self::reject(node, TurnErrorCode::StaleNonce, req),
            _ if !req.is_authenticated() => node.authenticate(req)?,
            _ if lifetime == 0 => node.add_event(TurnEvent::Close(SessionClose::RefreshZero)),
            _ => return Self::success(node, lifetime, req),
        }

        Ok(())
    }
}
