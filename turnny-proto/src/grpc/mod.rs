use core::net;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Bytes, BytesMut};
use grpc_ip_addr::Addr;
use prost::Message;

use crate::{
    coding::{CodingError, Decode},
    error::ProtoError,
};

// Imports prost_build generated code.
include!(concat!(env!("OUT_DIR"), "/isc.proto.rs"));

impl TurnGrpcMessage {
    pub fn bytes(self) -> Result<Bytes, CodingError> {
        let mut data = BytesMut::new();
        self.encode(&mut data).map_err(|_| CodingError::InvalidData)?;
        Ok(data.freeze())
    }
}

impl Decode for TurnGrpcMessage {
    type Output = Self;

    fn decode<B: bytes::Buf>(buffer: &mut B) -> Result<Self::Output, ProtoError> {
        let msg = <TurnGrpcMessage as prost::Message>::decode(buffer).map_err(|_| CodingError::InvalidData)?;
        Ok(msg)
    }
}

impl TryFrom<GrpcIpAddr> for SocketAddr {
    type Error = CodingError;

    fn try_from(grpcaddr: GrpcIpAddr) -> Result<Self, Self::Error> {
        let addr = match grpcaddr.addr {
            Some(addr) => addr,
            None => {
                tracing::error!("GRPC Address Not Found on the ByteFrames");
                return Err(CodingError::InvalidData)?;
            }
        };

        match addr {
            Addr::V4(IPv4 { ip, port }) => {
                let addr = IpAddr::V4(Ipv4Addr::from_bits(ip));
                Ok(SocketAddr::new(addr, port as u16))
            }
            Addr::V6(IPv6 { ip, port }) => {
                let bytes: [u8; 16] = match ip.try_into() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!("IPV6 addr to bytes conversion error - {:?}", e);
                        return Err(CodingError::InvalidData)?;
                    }
                };
                let addr = IpAddr::V6(Ipv6Addr::from(bytes));
                Ok(SocketAddr::new(addr, port as u16))
            }
        }
    }
}

impl TryFrom<SocketAddr> for GrpcIpAddr {
    type Error = CodingError;
    fn try_from(addr: net::SocketAddr) -> Result<Self, Self::Error> {
        let grpc_ip_addr = match addr {
            SocketAddr::V4(v4) => Some(Addr::V4(IPv4 {
                ip: v4.ip().to_bits(),
                port: v4.port() as u32,
            })),
            SocketAddr::V6(v6) => Some(Addr::V6(IPv6 {
                ip: v6.ip().octets().as_slice().to_vec(),
                port: v6.port() as u32,
            })),
        };

        Ok(GrpcIpAddr { addr: grpc_ip_addr })
    }
}
