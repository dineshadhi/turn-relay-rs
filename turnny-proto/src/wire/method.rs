use crate::{
    coding::{CodingError, Decode, Encode},
    error::ProtoError,
};
use bytes::{Buf, BufMut};

use super::{MAX_CHANNEL_NUM, MIN_CHANNEL_NUMBER};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MKind {
    Request,
    Success,
    Error,
}

// Method enum is missing (Send & Data) because it requires a response back to ensure delivery.
// We don't offer support for Send and Data. Only Indications are supported.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Method {
    Allocate(MKind),
    Permission(MKind),
    ChannelBind(MKind),
    Refresh(MKind),
    Stun(MKind),
    SendIndication,
    DataIndication,
    ChannelData(u16),
    Unknown(u16),
    // Send, Data - Not Supported
}

impl Method {
    pub(crate) fn is_unknown(&self) -> bool {
        matches!(self, Method::Unknown(_))
    }

    // Reads the method without advancing the buffer
    pub(crate) fn peek(buffer: &[u8]) -> Result<Self, ProtoError> {
        match buffer.remaining() < 2 {
            true => Err(ProtoError::NeedMoreData)?,
            false => Ok(u16::from_be_bytes(buffer.chunk()[..2].try_into().unwrap()).try_into()?),
        }
    }
}

impl TryFrom<u16> for Method {
    type Error = CodingError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0001 => Self::Stun(MKind::Request),
            0x0003 => Self::Allocate(MKind::Request),
            0x0008 => Self::Permission(MKind::Request),
            0x0009 => Self::ChannelBind(MKind::Request),
            0x0004 => Self::Refresh(MKind::Request),
            0x0006 | 0x0007 => return Err(CodingError::UnsupportedMethod), // Send & Data
            0x0016 => Self::SendIndication,
            0x0017 => Self::DataIndication,
            x if (MIN_CHANNEL_NUMBER..MAX_CHANNEL_NUM).contains(&x) => Self::ChannelData(x),
            x => Method::Unknown(x),
        })
    }
}

impl Decode for Method {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        Ok(u16::decode(buffer)?.try_into()?)
    }
}

impl Encode for Method {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        buffer.put_u16(u16::from(*self));
        Ok(())
    }
}

impl From<Method> for u16 {
    fn from(value: Method) -> Self {
        match value {
            Method::Stun(kind) => match kind {
                MKind::Request => 0x0001,
                MKind::Success => 0x0101,
                MKind::Error => 0x0111,
            },
            Method::Allocate(kind) => match kind {
                MKind::Request => 0x0003,
                MKind::Success => 0x0103,
                MKind::Error => 0x0113,
            },
            Method::Permission(kind) => match kind {
                MKind::Request => 0x0008,
                MKind::Success => 0x0108,
                MKind::Error => 0x0118,
            },
            Method::ChannelBind(kind) => match kind {
                MKind::Request => 0x0009,
                MKind::Success => 0x0109,
                MKind::Error => 0x0119,
            },
            Method::Refresh(kind) => match kind {
                MKind::Request => 0x0004,
                MKind::Success => 0x0104,
                MKind::Error => 0x0114,
            },
            Method::SendIndication => 0x0016,
            Method::DataIndication => 0x0017,
            Method::ChannelData(x) => x,
            Method::Unknown(x) => x,
        }
    }
}
