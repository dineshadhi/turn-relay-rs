use super::{ATTR_HEADER_LENGTH, error::TurnErrorCode, message::TranID, util};
use crate::{
    coding::{CodingError, Decode, Encode},
    compute_padding,
    error::ProtoError,
};
use anyhow::{Context, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
#[repr(u16)]
pub enum AKind {
    Data = 0x0013,
    XorPeerAddress = 0x0012,
    XorRelayAddress = 0x0016,
    XorMappedAddress = 0x0020,
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    ChannelNumber = 0x000c,
    Lifetime = 0x000d,
    Nonce = 0x0015,
    Realm = 0x0014,
    Origin = 0x802f,
    RequestedTransport = 0x0019,
    RequestedAddrFamily = 0x0017,
    Fingerprint = 0x8028,
    Unknown(u16),
}

impl AKind {
    const MAPPING: &'static [(AKind, u16)] = &[
        (AKind::Data, 0x0013),
        (AKind::XorPeerAddress, 0x0012),
        (AKind::XorRelayAddress, 0x0016),
        (AKind::XorMappedAddress, 0x0020),
        (AKind::MappedAddress, 0x0001),
        (AKind::Username, 0x0006),
        (AKind::MessageIntegrity, 0x0008),
        (AKind::ErrorCode, 0x0009),
        (AKind::ChannelNumber, 0x000c),
        (AKind::Lifetime, 0x000d),
        (AKind::Nonce, 0x0015),
        (AKind::Realm, 0x0014),
        (AKind::Origin, 0x802f),
        (AKind::RequestedTransport, 0x0019),
        (AKind::RequestedAddrFamily, 0x0017),
        (AKind::Fingerprint, 0x8028),
    ];

    pub fn from_u16(value: u16) -> Self {
        Self::MAPPING
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(kind, _)| *kind)
            .unwrap_or(Self::Unknown(value))
    }

    pub fn to_u16(self) -> Result<u16, ProtoError> {
        Ok(match self {
            Self::Unknown(_) => panic!("Unknown Attribute : to_u16"), // Should never happen
            _ => Self::MAPPING.iter().find(|(kind, _)| self == *kind).map(|(_, value)| *value).unwrap(),
        })
    }
}

impl Decode for AKind {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        let value = u16::decode(buffer)?;
        Ok(AKind::from_u16(value))
    }
}

impl Encode for AKind {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        self.to_u16()?.encode(buffer)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct StunAttrs {
    inner: Vec<(AKind, Bytes)>,
}

impl StunAttrs {
    pub fn is_attr<T: AttributeTrait>(&self) -> bool {
        self.inner.iter().any(|(akind, _)| *akind == T::akind())
    }

    // Checks if all attrs are present, if not sends the missing attr as error
    pub fn is_attrs(&self, akinds: Vec<AKind>) -> Result<(), AKind> {
        for kind in akinds {
            if !self.inner.iter().any(|(k, _)| *k == kind) {
                return Err(kind);
            }
        }
        Ok(())
    }

    pub fn get_attr<T: AttributeTrait>(&self, tid: &TranID) -> anyhow::Result<T::Inner> {
        self.inner
            .iter()
            .find(|(akind, _)| akind == &T::akind())
            .map(|(_, bytes)| T::decode(bytes.clone(), tid))
            .ok_or(CodingError::AttrNotFound)
            .context("get_attr failed for {akind}")?
    }

    pub fn set_attr<T: AttributeTrait>(&mut self, data: T::Inner, tid: &TranID) {
        let found = self.inner.iter_mut().find(|(akind, _)| *akind == T::akind());
        let replace = (T::akind(), T::encode(data, tid));

        match found {
            Some(val) => *val = replace,
            None => self.inner.push(replace),
        }
    }

    pub fn get_string(&self, tid: &TranID) -> anyhow::Result<String> {
        let mut res = String::new();
        for (akind, bytes) in &self.inner {
            let s: String = match akind {
                AKind::Data => format!("Data - {} bytes", bytes.len()),
                AKind::XorPeerAddress => format!("XorPeerAddr - {:?}", XorPeerAttr::decode(bytes.to_owned(), tid)?),
                AKind::XorRelayAddress => format!("XorRelayADdr - {:?}", XorRelayAttr::decode(bytes.to_owned(), tid)?),
                AKind::XorMappedAddress => format!("XorMappedAddr - {:?}", XorMappedAttr::decode(bytes.to_owned(), tid)?),
                AKind::MappedAddress => format!("MappedAddr : {:?}", MappedAttr::decode(bytes.to_owned(), tid)?),
                AKind::Username => format!("Username - {:?}", UsernameAttr::decode(bytes.to_owned(), tid)?),
                AKind::MessageIntegrity => "MessageIntegrity - {Redacted}".to_string(),
                AKind::ErrorCode => format!("ErrCode - {:?}", ErrorCodeAttr::decode(bytes.to_owned(), tid)?),
                AKind::ChannelNumber => format!("ChannelNumber - {}", ChannelNumberAttr::decode(bytes.to_owned(), tid)?),
                AKind::Lifetime => format!("ChannelNumber - {}", LifeTimeAttr::decode(bytes.to_owned(), tid)?),
                AKind::Nonce => format!("Nonce - {:?}", NonceAttr::decode(bytes.to_owned(), tid)?),
                AKind::Realm => format!("Realm - {:?}", RealmAttr::decode(bytes.to_owned(), tid)?),
                AKind::Origin => format!("Realm - {:?}", OriginAttr::decode(bytes.to_owned(), tid)?),
                AKind::RequestedTransport => format!("ReqTransport - {:?}", ReqTransportAttr::decode(bytes.to_owned(), tid)?),
                AKind::RequestedAddrFamily => format!("ReqAddrFamily - {:?}", ReqFamilyAddr::decode(bytes.to_owned(), tid)?),
                AKind::Fingerprint => format!("Fingerprint : {}", FingerprintAttr::decode(bytes.to_owned(), tid)?),
                AKind::Unknown(_) => "UnknownAttr".to_string(),
            };

            res = format!("{res} {s}");
        }

        Ok(res)
    }
}

impl Decode for StunAttrs {
    type Output = (Self, Option<usize>);
    // Returns the StunAttrs and also the starting index of the MI Attribute.
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        let mut inner = Vec::new();
        let mut mipos: Option<usize> = None; // Index position of the MI Attribute to be recorded
        let mut currpos: usize = 0;

        while buffer.has_remaining() {
            let akind = AKind::decode(buffer)?;
            let alen = usize::decode(buffer)?;
            let padding = compute_padding!(alen);

            match () {
                _ if buffer.remaining() < alen => return Err(ProtoError::NeedMoreData),
                _ if akind == AKind::MessageIntegrity => mipos = Some(currpos), // Recording the MI Attr position
                _ => (),
            }

            inner.push((akind, buffer.copy_to_bytes(alen)));
            buffer.advance(padding); // Advance the buffer to adjust for padding
            currpos += ATTR_HEADER_LENGTH + alen + padding; // Compute the position accordingly to track the position of MIAttr
        }

        Ok((Self { inner }, mipos))
    }
}

impl Encode for StunAttrs {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        for (akind, adata) in self.inner.iter() {
            akind.encode(buffer)?;
            adata.len().encode(buffer)?;
            // Its not Zero-Copy, this is the best I could do without fighting borrow-checker.
            // FIXME : Optimise this, because firefox only deals with Send Indication and DataChannels. So, the entire data will run via copy.
            buffer.put_slice(adata);
            buffer.put_bytes(0x00, compute_padding!(adata.len()));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp = 0x06,
    Udp = 0x11,
}

impl TryFrom<u8> for Transport {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> anyhow::Result<Self, Self::Error> {
        Ok(match value {
            0x06 => Self::Tcp,
            0x11 => Self::Udp,
            _ => bail!(CodingError::InvalidData),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddrFamily {
    IPv4 = 0x01,
    IPv6 = 0x02,
}

impl TryFrom<u8> for AddrFamily {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> anyhow::Result<Self, Self::Error> {
        Ok(match value {
            0x01 => Self::IPv4,
            0x02 => Self::IPv6,
            _ => bail!(CodingError::InvalidData),
        })
    }
}

pub trait AttributeTrait {
    type Inner;

    fn akind() -> AKind;
    fn decode(buffer: Bytes, tid: &TranID) -> anyhow::Result<Self::Inner>;
    fn encode(attr: Self::Inner, tid: &TranID) -> Bytes;
}

pub struct DataAttr;
impl AttributeTrait for DataAttr {
    type Inner = Bytes;

    fn akind() -> AKind {
        AKind::Data
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        Ok(buffer)
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        attr
    }
}

pub struct XorPeerAttr;
impl AttributeTrait for XorPeerAttr {
    type Inner = SocketAddr;

    fn akind() -> AKind {
        AKind::XorPeerAddress
    }

    fn decode(buffer: Bytes, tid: &TranID) -> anyhow::Result<Self::Inner> {
        util::parse_xor_address(buffer, tid)
    }

    fn encode(attr: Self::Inner, tid: &TranID) -> Bytes {
        util::bytes_xor_address(attr, tid)
    }
}

pub struct XorRelayAttr;
impl AttributeTrait for XorRelayAttr {
    type Inner = SocketAddr;

    fn akind() -> AKind {
        AKind::XorRelayAddress
    }

    fn decode(buffer: Bytes, tid: &TranID) -> anyhow::Result<Self::Inner> {
        util::parse_xor_address(buffer, tid)
    }

    fn encode(attr: Self::Inner, tid: &TranID) -> Bytes {
        util::bytes_xor_address(attr, tid)
    }
}

pub struct XorMappedAttr;
impl AttributeTrait for XorMappedAttr {
    type Inner = SocketAddr;

    fn akind() -> AKind {
        AKind::XorMappedAddress
    }

    fn decode(buffer: Bytes, tid: &TranID) -> anyhow::Result<Self::Inner> {
        util::parse_xor_address(buffer, tid)
    }

    fn encode(attr: Self::Inner, tid: &TranID) -> Bytes {
        util::bytes_xor_address(attr, tid)
    }
}

pub struct MappedAttr;
impl AttributeTrait for MappedAttr {
    type Inner = SocketAddr;

    fn akind() -> AKind {
        AKind::MappedAddress
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        util::parse_address(buffer)
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        util::bytes_address(attr)
    }
}

pub struct UsernameAttr;
impl AttributeTrait for UsernameAttr {
    type Inner = String;

    fn akind() -> AKind {
        AKind::Username
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let username = String::from_utf8(buffer.to_vec()).map_err(|_| CodingError::InvalidData)?;
        Ok(username.trim_matches(char::from(0)).to_string())
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        Bytes::copy_from_slice(attr.as_bytes())
    }
}

pub struct MessageIntegAttr;
impl AttributeTrait for MessageIntegAttr {
    type Inner = Bytes;

    fn akind() -> AKind {
        AKind::MessageIntegrity
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        Ok(buffer)
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        attr
    }
}

pub struct ErrorCodeAttr;
impl AttributeTrait for ErrorCodeAttr {
    type Inner = TurnErrorCode;

    fn akind() -> AKind {
        AKind::ErrorCode
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let mut chunk = buffer.clone();
        let _ = chunk.get_u16();
        let errcode = chunk.get_u16();

        TurnErrorCode::try_from(errcode)
    }

    fn encode(turnerror: Self::Inner, _: &TranID) -> Bytes {
        let code = turnerror.clone() as u32;
        let msg: &'static str = turnerror.into();

        let mut data = BytesMut::new();
        data.put_u32(code);
        data.put(msg.as_bytes());
        data.freeze()
    }
}

pub struct LifeTimeAttr;
impl AttributeTrait for LifeTimeAttr {
    type Inner = u32;

    fn akind() -> AKind {
        AKind::Lifetime
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let mut chunk = buffer.clone();
        Ok(chunk.get_u32())
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        let mut data = BytesMut::new();
        data.put_u32(attr);
        data.freeze()
    }
}

pub struct NonceAttr;
impl AttributeTrait for NonceAttr {
    type Inner = String;

    fn akind() -> AKind {
        AKind::Nonce
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let realm = String::from_utf8(buffer.to_vec()).map_err(|_| CodingError::InvalidData)?;
        Ok(realm.trim_matches(char::from(0)).to_string())
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        Bytes::copy_from_slice(attr.as_bytes())
    }
}

pub struct RealmAttr;
impl AttributeTrait for RealmAttr {
    type Inner = String;

    fn akind() -> AKind {
        AKind::Realm
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let realm = String::from_utf8(buffer.to_vec()).map_err(|_| CodingError::InvalidData)?;
        let s = realm.trim_matches(char::from(0)).to_string();
        Ok(s)
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        Bytes::copy_from_slice(attr.as_bytes())
    }
}

pub struct OriginAttr;
impl AttributeTrait for OriginAttr {
    type Inner = SocketAddr;

    fn akind() -> AKind {
        AKind::Origin
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        util::parse_address(buffer)
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        util::bytes_address(attr)
    }
}

pub struct ReqTransportAttr;
impl AttributeTrait for ReqTransportAttr {
    type Inner = Transport;

    fn akind() -> AKind {
        AKind::RequestedTransport
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        Transport::try_from(buffer[0])
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        let mut data = BytesMut::new();
        data.put_u8(attr as u8);
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.freeze()
    }
}

pub struct ReqFamilyAddr;
impl AttributeTrait for ReqFamilyAddr {
    type Inner = AddrFamily;

    fn akind() -> AKind {
        AKind::RequestedAddrFamily
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        AddrFamily::try_from(buffer[0])
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        let mut data = BytesMut::new();
        data.put_u8(attr as u8);
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.freeze()
    }
}

pub struct FingerprintAttr;
impl AttributeTrait for FingerprintAttr {
    type Inner = u32;

    fn akind() -> AKind {
        AKind::Fingerprint
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let mut chunk = buffer.clone();
        Ok(chunk.get_u32())
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        let mut data = BytesMut::new();
        data.put_u32(attr);
        data.freeze()
    }
}

pub struct ChannelNumberAttr;
impl AttributeTrait for ChannelNumberAttr {
    type Inner = u16;

    fn akind() -> AKind {
        AKind::ChannelNumber
    }

    fn encode(attr: Self::Inner, _: &TranID) -> Bytes {
        let mut data = BytesMut::new();
        data.put_u16(attr);
        data.put_u16(0x0000);
        data.freeze()
    }

    fn decode(buffer: Bytes, _: &TranID) -> anyhow::Result<Self::Inner> {
        let mut chunk = buffer.clone();
        Ok(chunk.get_u16())
    }
}
