use crate::{pipe_stream::WaitThenDyn, PinFuture};

pub trait Signalling: WaitThenDyn<Output = Option<String>> {
    fn send(&mut self, candidates: String) -> PinFuture<'_, ()>;
}
