use futures::future::LocalBoxFuture;

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

pub trait PipeStream: WaitThen<Output = Option<Vec<u8>>> + Control {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> LocalBoxFuture<'a, Result<(), Self::Error>>;
}
