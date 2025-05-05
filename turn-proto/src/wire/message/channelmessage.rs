use bytes::{Buf, BufMut, Bytes};

use crate::{
    coding::{Decode, Encode},
    compute_padding,
    error::ProtoError,
    wire::method::Method,
};

use super::StunMessage;

#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub channel: u16,
    pub data: Bytes,
}

impl Decode for ChannelMessage {
    type Output = Self;
    fn decode<B: Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        let channel = match Method::decode(buffer)? {
            Method::ChannelData(data) => data,
            _ => unreachable!(),
        };

        let length = u16::decode(buffer)? as usize;

        // NOTE : Padding is tricky in channel data. For UDP, there is no padding. Since UDP is a datagram, the remaining length will always be equal to
        // the actual Channel Data length. For TCP, we compute the padding accordingly. Sometime, the TCP data might be fragmented cutting away the padding,
        // we take care of this in StunMessage::decode() by skipping all the padding until we get the valid Method
        let padding = match buffer.remaining() {
            x if x == length => 0,         // UDP
            _ => compute_padding!(length), // TCP
        };

        if buffer.remaining() < length + padding {
            return Err(ProtoError::NeedMoreData);
        }

        let data = buffer.copy_to_bytes(length);

        assert!(buffer.remaining() >= padding);
        buffer.advance(padding);

        Ok(ChannelMessage { channel, data })
    }
}

impl Encode for ChannelMessage {
    fn encode<BM: BufMut>(&self, buffer: &mut BM) -> Result<(), ProtoError> {
        Method::ChannelData(self.channel).encode(buffer)?;
        let chunk = self.data.chunk();
        chunk.len().encode(buffer)?;
        buffer.put_slice(chunk);
        buffer.put_bytes(0x00, compute_padding!(chunk.len()));
        Ok(())
    }
}

impl From<ChannelMessage> for StunMessage {
    fn from(val: ChannelMessage) -> Self {
        StunMessage::Channel(val)
    }
}
