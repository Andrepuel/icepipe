pub mod agreement;
pub mod async_pipe_stream;
pub mod constants;
pub mod crypto_stream;
pub mod ice;
pub mod pipe_stream;
pub mod sctp;
pub mod signalling;
pub mod ws;

use std::future::Future;
use std::pin::Pin;

pub type DynResult<T> = Result<T, anyhow::Error>;
pub type PinFuture<'a, T> = Pin<Box<dyn Future<Output = DynResult<T>> + Send + 'a>>;
pub type PinFutureLocal<'a, T> = Pin<Box<dyn Future<Output = DynResult<T>> + 'a>>;
