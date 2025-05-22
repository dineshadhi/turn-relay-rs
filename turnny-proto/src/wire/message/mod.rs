pub mod channelmessage;
pub mod turnmessage;
pub use channelmessage::*;
pub use turnmessage::*;

use super::{TRAN_ID_LENGTH, method::Method, util};
use crate::{
    coding::{CodingError, Decode, Encode},
    error::ProtoError,
    wire::MAGIC_COOKIE,
};
use bytes::{Buf, BufMut, Bytes};
use std::ops::Deref;

#[macro_export]
macro_rules! is_attrs {
    ($req:ident, $($attr:ident,)*) => {
        $req.is_attrs(vec![$($attr::akind(),)*])
    };
}

#[derive(Clone)]
pub struct TranID(Bytes);

impl std::fmt::Debug for TranID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_string = self.0.iter().fold(String::new(), |mut str, val| {
            str = str + &format!("{val:02x}");
            str
        });
        write!(f, "{hex_string}")
    }
}

impl Decode for TranID {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        Ok(TranID(buffer.copy_to_bytes(TRAN_ID_LENGTH)))
    }
}

impl Encode for TranID {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        buffer.put_slice(&self.0);
        Ok(())
    }
}

impl Default for TranID {
    fn default() -> Self {
        TranID(util::generate_tid())
    }
}

impl Deref for TranID {
    type Target = Bytes;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct Cookie(u32);

impl Cookie {
    pub const MAGIC: Cookie = Cookie(MAGIC_COOKIE);

    fn encode<B: BufMut>(buffer: &mut B) -> Result<(), ProtoError> {
        buffer.put_u32(MAGIC_COOKIE);
        Ok(())
    }
}

impl Encode for Cookie {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        buffer.put_u32(self.0);
        Ok(())
    }
}

impl Decode for Cookie {
    type Output = Cookie;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        let val = buffer.try_get_u32().map_err(|_| ProtoError::NeedMoreData)?;
        match val {
            MAGIC_COOKIE => Ok(Cookie(val)),
            _ => Err(CodingError::InvalidCookie(val))?,
        }
    }
}

#[derive(Debug, Clone)]
pub enum StunMessage {
    Turn(TurnMessage),
    Channel(ChannelMessage),
}

impl Decode for StunMessage {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        // Advance till you find a valid method. This chips away any fragmented paddings from previous StunMessage, specially in TCP where the
        // paddings may get fragmented in to different segments.
        let method = loop {
            let method = Method::peek(buffer.chunk())?;
            match method.is_unknown() {
                true => match buffer.remaining() {
                    x if x > 0 => buffer.advance(1),
                    _ => return Err(ProtoError::NeedMoreData),
                },
                false => break method,
            }
        };

        Ok(match method {
            Method::ChannelData(_) => StunMessage::Channel(ChannelMessage::decode(buffer)?),
            _ => StunMessage::Turn(TurnMessage::decode(buffer)?),
        })
    }
}

impl Encode for StunMessage {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        match self {
            StunMessage::Turn(msg) => msg.encode(buffer),
            StunMessage::Channel(msg) => msg.encode(buffer),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::wire::{
        attribute::{MessageIntegAttr, UsernameAttr, XorPeerAttr},
        method::MKind,
    };
    use bytes::BytesMut;

    use super::*;
    const ALLOCATE_DUMP: &str = "000300882112a442415a4e555631705551464b77001900041100000000060044323a43543a313732393335383235323738303a3230303a39306438363634382d666637322d346162332d313732393335383235323737382d316335346333336264333565001400077274632e636f6d0000150010525256305859375847355462745a6c48000800143bb6ff776c115a45b2a8d9c378621ecd3c1cca62";
    // const CHALLENGE: &str = "000300742112a442415a4e555631705551464b77001900041100000000060044323a43543a313732393335383235323738303a3230303a39306438363634382d666637322d346162332d313732393335383235323737382d316335346333336264333565001400077274632e636f6d0000150010525256305859375847355462745a6c48";

    #[test]
    fn turnmsg_decode_test() {
        let allocate = hex::decode(ALLOCATE_DUMP).unwrap();
        // let challenge = hex::decode(CHALLENGE).unwrap();

        let mut buffer = Bytes::from(allocate.clone());
        let msg = StunMessage::decode(&mut buffer).unwrap();
        match msg {
            StunMessage::Turn(alloc) => {
                // assert_eq!(alloc.clone().challenge.unwrap().to_vec(), challenge);
                assert_eq!(alloc.method, Method::Allocate(MKind::Request));
                assert!(alloc.is_attr::<UsernameAttr>());
                assert_eq!(
                    alloc.get_attr::<UsernameAttr>().unwrap(),
                    "2:CT:1729358252780:200:90d86648-ff72-4ab3-1729358252778-1c54c33bd35e"
                );
                assert!(!alloc.is_attr::<XorPeerAttr>());
                assert!(alloc.is_attr::<MessageIntegAttr>());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_partial_decode_test() {
        let allocate = hex::decode(ALLOCATE_DUMP).unwrap();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&allocate[..25]);

        let mut cursor = std::io::Cursor::new(&mut buffer);
        assert_eq!(StunMessage::decode(&mut cursor).unwrap_err(), ProtoError::NeedMoreData);

        buffer.extend_from_slice(&allocate[25..]);
        let mut cursor = std::io::Cursor::new(&mut buffer);
        StunMessage::decode(&mut cursor).unwrap();
    }

    #[test]
    fn test_extra_decode_test() {
        let allocate = hex::decode(ALLOCATE_DUMP).unwrap();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&allocate[..]);
        buffer.extend_from_slice(&allocate[..25]);

        let mut cursor = std::io::Cursor::new(&mut buffer);
        assert!(StunMessage::decode(&mut cursor).ok().is_some());
        assert_eq!(StunMessage::decode(&mut cursor).unwrap_err(), ProtoError::NeedMoreData);

        buffer.extend_from_slice(&allocate[25..]);
        let mut cursor = std::io::Cursor::new(&mut buffer);
        StunMessage::decode(&mut cursor).unwrap();
    }

    #[test]
    fn cookie_encode() {
        let cookie = Cookie::MAGIC;
        let mut buffer = BytesMut::new();
        cookie.encode(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_ref(), &MAGIC_COOKIE.to_be_bytes());
    }
}
