use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::error::ProtoError;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CodingError {
    #[error("Invalid Magic Cookie {0}")]
    InvalidCookie(u32),

    #[error("Invalid Data")]
    InvalidData,

    #[error("Uknown Error Code {0}")]
    UnknownErrorCode(u16),

    #[error("AttrNotFound")]
    AttrNotFound,

    #[error("Unsupported Method")]
    UnsupportedMethod,
}

pub trait Encode {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError>;

    fn bytes(&self) -> Result<Bytes, ProtoError> {
        let mut data = BytesMut::new();
        self.encode(&mut data)?;
        Ok(data.freeze())
    }
}

pub trait Decode {
    type Output;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError>;
}

impl Encode for u16 {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        buffer.put_u16(*self);
        Ok(())
    }
}

impl Decode for u16 {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        buffer.try_get_u16().map_err(|_| ProtoError::NeedMoreData)
    }
}

impl Encode for usize {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        let val = *self as u16;
        val.encode(buffer)
    }
}

impl Decode for usize {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        Ok(u16::decode(buffer)? as usize)
    }
}
