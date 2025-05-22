use crate::coding::CodingError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ProtoError {
    #[error("Coding Error {0}")]
    CodingError(#[from] CodingError),

    #[error("Need More Data")]
    NeedMoreData,

    #[error("MI Error {0}")]
    MessageIntegrityFailed(String),

    #[error("Attribute Missing")]
    AttrMissing,

    #[error("Processing Error")]
    ProcessingError,
}
