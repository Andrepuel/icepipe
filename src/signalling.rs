use crate::{error::TimeoutError, pipe_stream::WaitThen};
use futures::future::LocalBoxFuture;
use std::io;

pub trait Signalling: WaitThen<Output = Option<String>>
where
    Self::Error: Into<SignalingError>,
{
    fn send(&mut self, candidates: String) -> LocalBoxFuture<'_, Result<(), Self::Error>>;
}

#[derive(thiserror::Error, Debug)]
pub enum SignalingError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    ProtocolError(Box<dyn std::error::Error + Send + Sync>),
}
impl From<SignalingError> for std::io::Error {
    fn from(value: SignalingError) -> Self {
        match value {
            SignalingError::Timeout(e) => e.into(),
            SignalingError::Io(e) => e,
            SignalingError::ProtocolError(e) => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
}
