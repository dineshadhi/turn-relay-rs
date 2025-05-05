use std::{ops::Deref, time::Instant};

use crate::is_expired;

pub mod attribute;
pub mod error;
pub mod message;
pub(crate) mod method;
pub(crate) mod util;

#[derive(Debug, Clone)]
pub struct Realm(pub String);

impl Default for Realm {
    fn default() -> Self {
        Realm(String::from("turn-rs"))
    }
}

impl Realm {
    pub fn new(val: &str) -> Self {
        Realm(val.into())
    }
}

#[derive(Debug, Clone)]
pub struct Nonce {
    inner: String,
    created_at: Instant,
}

impl Default for Nonce {
    fn default() -> Self {
        Self {
            inner: util::generate_nonce(),
            created_at: Instant::now(),
        }
    }
}

impl Nonce {
    pub fn get(&mut self, expire_time: u64) -> &String {
        if is_expired!(self.created_at, expire_time) {
            self.inner = util::generate_nonce();
        }
        &self.inner
    }
}

impl From<String> for Realm {
    fn from(value: String) -> Self {
        Realm(value)
    }
}

impl Deref for Realm {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[macro_export]
macro_rules! compute_padding {
    ($val:expr) => {
        match $val % 4 {
            0 => 0,
            x => 4 - x,
        }
    };
}

const STUN_HEADER_LEN: usize = 20;

const TRAN_ID_LENGTH: usize = 12;
const MI_ATTR_LENGTH: usize = 24;
const ATTR_HEADER_LENGTH: usize = 4;

const MAGIC_COOKIE: u32 = 0x2112A442u32;
const MAGIC_COOKIE_MASK: u16 = 0x2112u16;

const MIN_CHANNEL_NUMBER: u16 = 0x4000;
const MAX_CHANNEL_NUM: u16 = 0x7FFE;

const IPV4_ADDRESS_FAMILY: u8 = 0x01;
const IPV6_ADDRESS_FAMILY: u8 = 0x02;
