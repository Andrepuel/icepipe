use crate::PinFuture;

pub trait Signalling {
    fn send(&mut self, candidates: String) -> PinFuture<'_, ()>;
    fn recv(&mut self) -> PinFuture<'_, String>;
}
