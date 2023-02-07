use crate::{error::TimeoutError, signalling::SignalingError};
use futures::future::LocalBoxFuture;
use std::io;

pub trait WaitThen {
    type Value;
    type Output;
    type Error: std::error::Error;

    fn wait(&mut self) -> LocalBoxFuture<'_, Result<Self::Value, Self::Error>>;
    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> LocalBoxFuture<'a, Result<Self::Output, Self::Error>>;
}

pub trait Control: WaitThen {
    fn close(&mut self) -> LocalBoxFuture<'_, Result<(), Self::Error>>;
    fn rx_closed(&self) -> bool;
}

pub trait PipeStream: WaitThen<Output = Option<Vec<u8>>> + Control
where
    Self::Error: Into<StreamError>,
{
    fn send<'a>(&'a mut self, data: &'a [u8]) -> LocalBoxFuture<'a, Result<(), Self::Error>>;
}

#[derive(thiserror::Error, Debug)]
pub enum StreamError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    SignalingError(SignalingError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}
impl From<SignalingError> for StreamError {
    fn from(value: SignalingError) -> Self {
        match value {
            SignalingError::Io(e) => e.into(),
            SignalingError::Timeout(e) => e.into(),
            e @ SignalingError::ProtocolError(_) => Self::SignalingError(e),
        }
    }
}
pub type StreamResult<T> = Result<T, StreamError>;
