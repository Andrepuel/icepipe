use crate::pipe_stream::WaitThen;
use futures::future::BoxFuture;

pub trait Signalling: WaitThen<Output = Option<String>> {
    fn send(&mut self, candidates: String) -> BoxFuture<'_, Result<(), Self::Error>>;
}
