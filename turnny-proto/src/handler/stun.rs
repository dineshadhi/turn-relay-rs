use crate::{
    error::ProtoError,
    events::TurnEvent,
    node::TurnNode,
    wire::{
        attribute::XorMappedAttr,
        message::TurnMessage,
        method::{MKind, Method},
    },
};

pub struct Stun;

impl Stun {
    pub fn process(sm: &mut TurnNode, req: TurnMessage) -> Result<(), ProtoError> {
        let mut resp = req.extend(Method::Stun(MKind::Success));
        resp.set_attr::<XorMappedAttr>(sm.remote);
        sm.add_event(TurnEvent::SendToClient(resp.into()));
        tracing::info!("Stun Success");
        Ok(())
    }
}
