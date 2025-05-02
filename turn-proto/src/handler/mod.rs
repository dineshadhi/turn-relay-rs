use crate::{
    error::ProtoError,
    events::TurnEvent::SendToClient,
    node::TurnNode,
    wire::{
        attribute::{DataAttr, XorPeerAttr},
        error::TurnErrorCode,
        message::{ChannelMessage, StunMessage, TranID, turnmessage::TurnMessage},
        method::{MKind::Request, Method},
    },
};
use allocate::Allocate;
use bytes::Bytes;
use channelbind::ChannelBind;
use channeldata::ChannelData;
use permission::Permission;
use refresh::Refresh;
use sendindication::SendIndication;
use std::net::SocketAddr;
use stun::Stun;

pub struct Handler;
pub mod allocate;
pub mod channelbind;
pub mod channeldata;
pub mod permission;
pub mod refresh;
pub mod sendindication;
pub mod stun;

impl Handler {
    pub fn handle_turn_msg(node: &mut TurnNode, req: TurnMessage) -> Result<(), ProtoError> {
        match req.method {
            Method::Stun(Request) => Stun::process(node, req),
            Method::Allocate(Request) => Allocate::process(node, req, None),
            Method::Permission(Request) => Permission::process(node, req),
            Method::SendIndication => SendIndication::process(node, req),
            Method::ChannelBind(Request) => ChannelBind::process(node, req),
            Method::Refresh(Request) => Refresh::process(node, req),
            _ => {
                tracing::error!("Method cannnot be processed {:?}", req.method);
                Err(ProtoError::ProcessingError)
            }
        }
    }

    pub fn handle_stun_msg(node: &mut TurnNode, msg: StunMessage) -> Result<(), ProtoError> {
        match msg {
            StunMessage::Turn(msg) => msg.in_scope(|msg| Self::handle_turn_msg(node, msg)),
            StunMessage::Channel(msg) => ChannelData::process(node, msg),
        }
    }

    pub fn handle_data_from_peer(node: &mut TurnNode, peer_addr: SocketAddr, data: Bytes) -> Result<(), ProtoError> {
        if !node.is_peer(&peer_addr) {
            tracing::error!("Error relaying data : not a peer {}", peer_addr);
            return Ok(());
        }

        let msg: StunMessage = match node.get_bound_channel(&peer_addr) {
            Some(channel) => ChannelMessage { channel, data }.into(),
            None => {
                let mut msg = TurnMessage::new(Method::DataIndication, TranID::default());
                msg.set_attr::<XorPeerAttr>(peer_addr);
                msg.set_attr::<DataAttr>(data);
                msg.into()
            }
        };

        node.add_event(SendToClient(msg));
        Ok(())
    }

    pub fn reject_msg(node: &mut TurnNode, msg: TurnMessage, code: TurnErrorCode) -> Result<(), ProtoError> {
        match msg.method {
            Method::Allocate(Request) => Allocate::reject(node, code, msg),
            Method::Permission(Request) => Permission::reject(node, code, msg),
            Method::ChannelBind(Request) => ChannelBind::reject(node, code, msg),
            Method::Refresh(Request) => Refresh::reject(node, code, msg),
            _ => unreachable!(),
        };

        Ok(())
    }
}
