use crate::{
    coding::{Decode, Encode},
    error::ProtoError,
    wire::{
        MI_ATTR_LENGTH, STUN_HEADER_LEN,
        attribute::{AKind, AttributeTrait, MessageIntegAttr, RealmAttr, StunAttrs, UsernameAttr},
        method::Method,
    },
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::hmac::{self, HMAC_SHA1_FOR_LEGACY_USE_ONLY, Key, sign};
use tracing::{Level, Span, span};

use super::{Cookie, StunMessage, TranID};

#[derive(Clone, Debug)]
pub struct TurnMessage {
    pub method: Method,
    pub tid: TranID,
    pub attrs: StunAttrs,
    // Challenge blob to verify message integrity. It is optional, because only few TURN methods have MI.
    pub challenge: Option<Bytes>,
    authenticated: bool,
    credential: Option<Vec<u8>>,
    pub(crate) span: Span,
}

impl TurnMessage {
    pub fn get_span(method: Method) -> Span {
        match method {
            Method::Allocate(_) => span!(Level::INFO, "Allocate"),
            Method::Permission(_) => span!(Level::INFO, "Permission"),
            Method::ChannelBind(_) => span!(Level::INFO, "ChannelBind"),
            Method::Refresh(_) => span!(Level::INFO, "Refresh"),
            Method::Stun(_) => span!(Level::INFO, "Stun"),
            Method::SendIndication => span!(Level::TRACE, "SendIndication"),
            Method::DataIndication => span!(Level::TRACE, "DataIndication"),
            Method::ChannelData(_) => span!(Level::TRACE, "ChannelData"),
            Method::Unknown(_) => todo!(),
        }
    }
    pub fn new(method: Method) -> Self {
        Self {
            method,
            tid: TranID::default(),
            attrs: StunAttrs::default(),
            challenge: None,
            authenticated: false,
            credential: None,
            span: Self::get_span(method),
        }
    }

    // Extends the existing TURN Message in to a another message with the provided Method.
    // Extremely useful when creating valid Responses for TURN Requests.
    pub fn extend(&self, method: Method) -> TurnMessage {
        TurnMessage {
            method,
            tid: self.tid.clone(),
            attrs: Default::default(),
            challenge: None,
            authenticated: false,
            credential: self.credential.clone(), // We also copy credentials, make sure responses doesn't need password when computing MI.
            span: self.span.clone(),
        }
    }

    pub fn is_attrs(&self, attrs: Vec<AKind>) -> Result<(), AKind> {
        self.attrs.is_attrs(attrs)
    }

    pub fn is_attr<T: AttributeTrait>(&self) -> bool {
        self.attrs.is_attr::<T>()
    }

    pub fn get_attr<T: AttributeTrait>(&self) -> Result<T::Inner, ProtoError> {
        self.attrs.get_attr::<T>(&self.tid).map_err(|_| ProtoError::AttrMissing)
    }

    pub fn set_attr<T: AttributeTrait>(&mut self, data: T::Inner) {
        self.attrs.set_attr::<T>(data, &self.tid);
    }

    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    // Convenient func to run functions inside a span assigned to this TurnMessage
    pub fn in_scope<F: FnOnce(Self) -> T, T>(self, f: F) -> T {
        self.span.clone().in_scope(|| f(self))
    }

    pub fn authenticate(&mut self, password: &str) -> Result<(), ProtoError> {
        let credential = match &self.credential {
            Some(cred) => cred,
            None => &self
                .compute_credential(password)
                .map_err(|e| ProtoError::MessageIntegrityFailed(format!("{e}")))?,
        };

        let challenge = match &self.challenge {
            Some(challenge) => challenge,
            None => return Err(ProtoError::MessageIntegrityFailed("No challenge blob".into())),
        };

        let key = hmac::Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, credential);
        let tag = sign(&key, challenge);

        let integbytes = self
            .get_attr::<MessageIntegAttr>()
            .map_err(|e| ProtoError::MessageIntegrityFailed(format!("{e}")))?;

        match () {
            _ if tag.as_ref() == integbytes => {
                self.authenticated = true;
                Ok(())
            }
            _ => Err(ProtoError::MessageIntegrityFailed("MI Check Failed".into())),
        }
    }

    pub(crate) fn compute_credential(&mut self, password: &str) -> anyhow::Result<Vec<u8>> {
        let turnusername = self.get_attr::<UsernameAttr>()?;
        let realm = self.get_attr::<RealmAttr>()?;
        let credential = turnusername + ":" + &realm + ":" + password;
        let credential = md5::compute(credential).to_vec();
        self.credential = Some(credential.clone()); // Cache the credential
        Ok(credential)
    }

    pub(crate) fn compute_integrity(&self) -> Result<Bytes, ProtoError> {
        let credential = match &self.credential {
            Some(cred) => cred,
            None => {
                return Err(ProtoError::MessageIntegrityFailed(
                    "Compute Integrity Failed : TurnMessage is not configured with credential".into(),
                ));
            }
        };

        let mut buffer = Vec::new();
        self.encode(&mut buffer)?;

        let attrlen = buffer.len() - STUN_HEADER_LEN; // Length of the attributes
        let modlen: u16 = (attrlen + MI_ATTR_LENGTH) as u16; // Adding additional length for MI Attr that will be added after computing integrity

        let modlenbytes = modlen.to_be_bytes();
        buffer[2] = modlenbytes[0];
        buffer[3] = modlenbytes[1];

        let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, credential);
        let tag = sign(&key, &buffer);

        Ok(Bytes::copy_from_slice(tag.as_ref()))
    }
}

impl Decode for TurnMessage {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        // Order of decoding is important.
        let method = Method::decode(buffer)?;
        let attrlen = usize::decode(buffer)?;
        let _cookie = Cookie::decode(buffer)?;
        let tid = TranID::decode(buffer)?;

        let attrbytes = match buffer.remaining() {
            remaining if (remaining < attrlen) => return Err(ProtoError::NeedMoreData)?,
            _ => buffer.copy_to_bytes(attrlen), // Zero-Copy if underlying B is Bytes
        };

        // Create a cursor so that attrbytes doesn't advance. We need it in place to compute Challenge blob.
        let mut cursor = std::io::Cursor::new(&attrbytes);
        let (attrs, mipos) = StunAttrs::decode(&mut cursor)?;

        // Compute the challege blob if Message Integrity is present in the attrlist;
        let challenge = match mipos {
            Some(mipos) => {
                let mut challenge = BytesMut::new();
                let modlen = mipos + MI_ATTR_LENGTH; // Modified length of the challege. Only the length till the MIAttr and ignore all attrs after it.
                // Filling Stun Header
                method.encode(&mut challenge)?;
                modlen.encode(&mut challenge)?;
                Cookie::encode(&mut challenge)?;
                tid.encode(&mut challenge)?;
                // Attrs till mi pos
                challenge.extend_from_slice(&attrbytes[..mipos]);
                Some(challenge.freeze())
            }
            _ => None,
        };

        Ok(Self {
            method,
            tid,
            attrs,
            challenge,
            authenticated: false,
            credential: None,
            span: Self::get_span(method),
        })
    }
}

impl Encode for TurnMessage {
    fn encode<B: BufMut>(&self, buffer: &mut B) -> Result<(), ProtoError> {
        let mut attrbytes = BytesMut::new();
        self.attrs.encode(&mut attrbytes)?;
        let attrbytes = attrbytes.freeze();

        self.method.encode(buffer)?;
        attrbytes.len().encode(buffer)?;
        Cookie::MAGIC.encode(buffer)?;
        self.tid.encode(buffer)?;
        buffer.put_slice(&attrbytes);

        Ok(())
    }
}

impl From<TurnMessage> for StunMessage {
    fn from(val: TurnMessage) -> Self {
        StunMessage::Turn(val)
    }
}
