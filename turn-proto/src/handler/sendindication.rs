use crate::{
    error::ProtoError,
    events::TurnEvent::SendToPeer,
    is_attrs,
    node::TurnNode,
    wire::{
        attribute::{AttributeTrait, DataAttr, XorPeerAttr},
        message::TurnMessage,
    },
};

pub struct SendIndication;

impl SendIndication {
    pub fn process(node: &mut TurnNode, msg: TurnMessage) -> Result<(), ProtoError> {
        if let Err(e) = is_attrs!(msg, XorPeerAttr, DataAttr,) {
            tracing::error!("Send Indication Failed : Missing Attrs {:?}", e);
            return Ok(());
        }

        let peer_addr = msg.get_attr::<XorPeerAttr>()?;
        let data = msg.get_attr::<DataAttr>()?;

        match () {
            _ if !node.is_peer(&peer_addr) => tracing::error!("SI Failed : Permission Invalid - {}", peer_addr),
            _ => node.add_event(SendToPeer(peer_addr, data)),
        }

        Ok(())
    }
}
