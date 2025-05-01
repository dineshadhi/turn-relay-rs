use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::bail;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::{Rng, distr::Alphanumeric, rng};

use super::{IPV4_ADDRESS_FAMILY, IPV6_ADDRESS_FAMILY, MAGIC_COOKIE, MAGIC_COOKIE_MASK};

pub fn generate_tid() -> Bytes {
    let tid: String = rand::rng().sample_iter(&Alphanumeric).take(12).map(char::from).collect();
    Bytes::from(tid)
}

pub fn parse_xor_address(data: Bytes, tid: &Bytes) -> anyhow::Result<SocketAddr> {
    let mut buffer = Bytes::clone(&data);
    _ = buffer.get_u8();

    let family = buffer.get_u8();

    match family {
        IPV4_ADDRESS_FAMILY => {
            if buffer.remaining() < 6 {
                bail!("Malformed XOR Address - IPV4 Length Check Failed")
            }

            let port: u16 = buffer.get_u16() ^ MAGIC_COOKIE_MASK;
            let ip: u32 = buffer.get_u32() ^ MAGIC_COOKIE;

            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(ip)), port))
        }
        IPV6_ADDRESS_FAMILY => {
            if buffer.remaining() < 18 {
                bail!("Malformed XOR Address - IPV6 Length Check Failed")
            }

            let port: u16 = buffer.get_u16() ^ MAGIC_COOKIE_MASK;

            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(&tid);

            let ip = buffer.get_u128() ^ u128::from_be_bytes(mask);

            let addr = IpAddr::V6(Ipv6Addr::from_bits(ip));
            Ok(SocketAddr::new(addr, port))
        }
        _ => bail!("parse_xor_addr : Invalid IPAddr Family"),
    }
}

pub fn bytes_xor_address(addr: SocketAddr, tid: &Bytes) -> Bytes {
    let mut data = BytesMut::new();
    data.put_u8(0x00);

    match addr {
        SocketAddr::V4(ipv4) => {
            data.put_u8(IPV4_ADDRESS_FAMILY);

            let port: u16 = ipv4.port() ^ MAGIC_COOKIE_MASK;
            let ip: u32 = u32::from_be_bytes(ipv4.ip().octets()) ^ MAGIC_COOKIE;

            data.put_u16(port);
            data.put_u32(ip);
        }
        SocketAddr::V6(ipv6) => {
            data.put_u8(IPV6_ADDRESS_FAMILY);

            let port: u16 = ipv6.port() ^ MAGIC_COOKIE_MASK;

            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(&tid);

            let ip = u128::from_be_bytes(ipv6.ip().octets()) ^ u128::from_be_bytes(mask);

            data.put_u16(port);
            data.put_u128(ip);
        }
    };

    data.freeze()
}

pub fn parse_address(data: Bytes) -> anyhow::Result<SocketAddr> {
    let mut buffer = Bytes::clone(&data);
    _ = buffer.get_u8();

    let family = buffer.get_u8();

    match family {
        IPV4_ADDRESS_FAMILY => {
            let port: u16 = buffer.get_u16();
            let ip: u32 = buffer.get_u32();

            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from_bits(ip)), port))
        }
        IPV6_ADDRESS_FAMILY => {
            let port: u16 = buffer.get_u16();
            let ip = buffer.get_u128();

            let addr = IpAddr::V6(Ipv6Addr::from_bits(ip));
            Ok(SocketAddr::new(addr, port))
        }
        _ => bail!("parse_address : Invalid IPAddr Family"),
    }
}

pub fn bytes_address(addr: SocketAddr) -> Bytes {
    let mut data = BytesMut::new();
    data.put_u8(0x00);

    match addr {
        SocketAddr::V4(ipv4) => {
            data.put_u8(IPV4_ADDRESS_FAMILY);
            let port: u16 = ipv4.port();
            let ip: u32 = u32::from_be_bytes(ipv4.ip().octets());

            data.put_u16(port);
            data.put_u32(ip);
        }
        SocketAddr::V6(ipv6) => {
            data.put_u8(IPV4_ADDRESS_FAMILY);

            let port: u16 = ipv6.port();
            let ip = u128::from_be_bytes(ipv6.ip().octets());

            data.put_u16(port);
            data.put_u128(ip);
        }
    };

    data.freeze()
}

pub fn generate_nonce() -> String {
    let s: String = rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect();
    s
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // 103.148.33.185 - 54110
    const XOR_ADDRESS: Bytes = Bytes::from_static(&[0x00, 0x01, 0xf2, 0x4c, 0x46, 0x86, 0x85, 0xfb]);

    #[test]
    fn xor_addr_test() {
        let port = 54110;
        let actual = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(103, 148, 33, 185)), port);
        let result = parse_xor_address(XOR_ADDRESS, &XOR_ADDRESS).unwrap();

        assert_eq!(actual, result);
    }
}
