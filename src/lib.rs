pub mod agreement;
pub mod async_pipe_stream;
pub mod connect;
pub mod constants;
pub mod crypto_stream;
pub mod ice;
pub mod pipe_stream;
pub mod sctp;
pub mod signalling;
pub mod ws;

pub use connect::connect;

pub trait IntoIoError: Into<std::io::Error> + Send + Sync + 'static {
    fn kind(&self) -> std::io::ErrorKind;
}
