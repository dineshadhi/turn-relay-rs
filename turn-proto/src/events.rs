use crate::wire::message::{StunMessage, turnmessage::TurnMessage};
use bytes::{Buf, Bytes};
use std::{fmt::Debug, net::SocketAddr};

#[derive(Debug)]
pub enum SessionClose {
    RefreshZero,
    LifetimeExpired,
}

// State Machine --> Service
pub enum TurnEvent {
    /// Send the Response to Client
    SendToClient(StunMessage),
    /// TurnProto requires authentication to verify the message. Implementations must provide password on TurnNode::auth_msg()
    NeedsAuth(TurnMessage),
    /// Needs Port Allocation. Implementation must provide a valid SocketAddr on TurnNode::alloc_addr()
    NeedsAllocation(TurnMessage),
    /// Checks if a permission is valid if the peer_addr is different from the relay_addr. Implementation must issue permission on TurnNode::issue_permission()
    NeedsPermission(TurnMessage),
    /// Request to relay the data to the session attached to the address allcoated to the peer
    SendToPeer(SocketAddr, Bytes),
    /// Session is closed.
    Close(SessionClose),
}

pub enum InputEvent<B: Buf> {
    NetworkBytes(B),
    DataFromPeer(SocketAddr, Bytes),
}

impl Debug for TurnEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TurnEvent::SendToClient(_) => "SendToClient",
            TurnEvent::NeedsAuth(_) => "NeedsAuth",
            TurnEvent::NeedsAllocation(_) => "NeedsAllocation",
            TurnEvent::NeedsPermission(_) => "IssuePermission",
            TurnEvent::SendToPeer(_, _) => "RelayDataToPeer",
            TurnEvent::Close(_) => "Close",
        };
        write!(f, "{s}")
    }
}
