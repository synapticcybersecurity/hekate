use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid encstring format: {0}")]
    InvalidEncString(&'static str),

    #[error("crypto operation failed")]
    Crypto,

    #[error("kdf failure: {0}")]
    Kdf(String),

    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
}

pub type Result<T> = std::result::Result<T, Error>;
