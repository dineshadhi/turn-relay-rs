use crate::{error::ProtoError, events::TurnEvent, node::TurnNode, wire::message::ChannelMessage};

pub(crate) struct ChannelData;

impl ChannelData {
    pub fn process(node: &mut TurnNode, msg: ChannelMessage) -> Result<(), ProtoError> {
        match node.get_bound_peer_addr(&msg.channel) {
            Some(addr) => node.add_event(TurnEvent::SendToPeer(addr, msg.data)),
            None => tracing::error!("no peer_addr bound to channel {}", msg.channel),
        }

        Ok(())
    }
}
