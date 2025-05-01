use std::error::Error;

use anyhow::*;
use bytes::Bytes;

use crate::{coding::CodingError, error::ProtoError};

#[derive(Debug, PartialEq, Clone)]
pub enum TurnErrorCode {
    TryAlternate = 0x0300,
    BadRequest = 0x0400,
    Unauthorized = 0x0401,
    Forbidden = 0x0403,
    RequestTimedout = 0x0408,
    UnknownAttribute = 0x0414,
    AllocationMismatch = 0x0425,
    StaleNonce = 0x0426,
    AddressFamilyNotSupported = 0x0428,
    WrongCredentials = 0x0429,
    UnsupportedTransportAddress = 0x042A,
    AllocationQuotaReached = 0x0456,
    ServerError = 0x0500,
    InsufficientCapacity = 0x0508,
    UnknownError,
}

impl TryFrom<&Bytes> for TurnErrorCode {
    type Error = anyhow::Error;

    fn try_from(value: &Bytes) -> std::result::Result<Self, Self::Error> {
        if value.len() >= 2 {
            let code = u16::from_be_bytes([value[0], value[2]]);
            Self::try_from(code)
        } else {
            Err(anyhow!(ProtoError::NeedMoreData)).context("TurnErrorCode::try_from::Bytes")
        }
    }
}

impl TryFrom<u16> for TurnErrorCode {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0300 => TurnErrorCode::TryAlternate,
            0x0400 => TurnErrorCode::BadRequest,
            0x0401 => TurnErrorCode::Unauthorized,
            0x0403 => TurnErrorCode::Forbidden,
            0x0408 => TurnErrorCode::RequestTimedout,
            0x0414 => TurnErrorCode::UnknownAttribute,
            0x0425 => TurnErrorCode::AllocationMismatch,
            0x0426 => TurnErrorCode::StaleNonce,
            0x0428 => TurnErrorCode::AddressFamilyNotSupported,
            0x0429 => TurnErrorCode::WrongCredentials,
            0x042A => TurnErrorCode::UnsupportedTransportAddress,
            0x0456 => TurnErrorCode::AllocationQuotaReached,
            0x0500 => TurnErrorCode::ServerError,
            0x0508 => TurnErrorCode::InsufficientCapacity,
            _ => return Err(anyhow!(CodingError::UnknownErrorCode(value)).context("TurnErrorCode::try_from::u16 - Unknown Method")),
        })
    }
}

impl From<&str> for TurnErrorCode {
    fn from(value: &str) -> Self {
        match value {
            "TryAlternate" => TurnErrorCode::TryAlternate,
            "BadRequest" => TurnErrorCode::BadRequest,
            "UNAUTHROIZED" => TurnErrorCode::Unauthorized,
            "Forbidden" => TurnErrorCode::Forbidden,
            "RequestTimedout" => TurnErrorCode::RequestTimedout,
            "UnknownAttribute" => TurnErrorCode::UnknownAttribute,
            "AllocationMismatch" => TurnErrorCode::AllocationMismatch,
            "StaleNonce" => TurnErrorCode::StaleNonce,
            "AddressFamilyNotSupported" => TurnErrorCode::AddressFamilyNotSupported,
            "WrongCredentials" => TurnErrorCode::WrongCredentials,
            "UnsupportedTransportAddress" => TurnErrorCode::UnsupportedTransportAddress,
            "AllocationQuotaReached" => TurnErrorCode::AllocationQuotaReached,
            "ServerError" => TurnErrorCode::ServerError,
            "InsufficientCapacity" => TurnErrorCode::InsufficientCapacity,
            _ => TurnErrorCode::UnknownError,
        }
    }
}

impl From<TurnErrorCode> for &'static str {
    fn from(value: TurnErrorCode) -> Self {
        match value {
            TurnErrorCode::TryAlternate => "TryAlternate",
            TurnErrorCode::BadRequest => "BadRequest",
            TurnErrorCode::Unauthorized => "UNAUTHROIZED",
            TurnErrorCode::Forbidden => "Forbidden",
            TurnErrorCode::RequestTimedout => "RequestTimedout",
            TurnErrorCode::UnknownAttribute => "UnknownAttribute",
            TurnErrorCode::AllocationMismatch => "AllocationMismatch",
            TurnErrorCode::StaleNonce => "StaleNonce",
            TurnErrorCode::AddressFamilyNotSupported => "AddressFamilyNotSupported",
            TurnErrorCode::WrongCredentials => "WrongCredentials",
            TurnErrorCode::UnsupportedTransportAddress => "UnsupportedTransportAddress",
            TurnErrorCode::AllocationQuotaReached => "AllocationQuotaReached",
            TurnErrorCode::ServerError => "ServerError",
            TurnErrorCode::InsufficientCapacity => "InsufficientCapacity",
            TurnErrorCode::UnknownError => "UnknownError",
        }
    }
}

impl std::fmt::Display for TurnErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let codestr: &'static str = self.clone().into();
        write!(f, "{}", codestr)
    }
}

impl Error for TurnErrorCode {}
