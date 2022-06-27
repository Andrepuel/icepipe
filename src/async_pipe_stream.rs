use crate::pipe_stream::{Control, PipeStream, WaitThen};
use futures::future::ready;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub type DynAsyncRead = Pin<Box<dyn AsyncRead>>;
pub type DynAsyncWrite = Pin<Box<dyn AsyncWrite>>;

pub struct AsyncPipeStream {
    input: Pin<Box<dyn AsyncRead>>,
    output: Pin<Box<dyn AsyncWrite>>,
    rx_shut: bool,
    buf: Vec<u8>,
}
impl AsyncPipeStream {
    pub fn new<I, O>(input: I, output: O) -> AsyncPipeStream
    where
        I: AsyncRead + 'static,
        O: AsyncWrite + 'static,
    {
        let stdin = Box::pin(input);
        let stdout = Box::pin(output);

        AsyncPipeStream::new_dyn(stdin, stdout)
    }

    pub fn new_dyn(input: DynAsyncRead, output: DynAsyncWrite) -> AsyncPipeStream {
        AsyncPipeStream {
            input,
            output,
            rx_shut: false,
            buf: Vec::new(),
        }
    }

    pub fn stdio() -> AsyncPipeStream {
        AsyncPipeStream::new(tokio::io::stdin(), tokio::io::stdout())
    }
}
impl PipeStream for AsyncPipeStream {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> crate::PinFutureLocal<'a, ()> {
        Box::pin(async move {
            self.output.write_all(data).await?;
            Ok(())
        })
    }
}
impl WaitThen for AsyncPipeStream {
    type Value = usize;
    type Output = Option<Vec<u8>>;

    fn wait(&mut self) -> crate::PinFutureLocal<'_, Self::Value> {
        self.buf.resize(4096, 0);
        Box::pin(async move {
            let n = self.input.read(&mut self.buf).await?;
            Ok(n)
        })
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> crate::PinFutureLocal<'a, Self::Output> {
        if *value == 0 {
            self.rx_shut = true;
            return Box::pin(ready(Ok(None)));
        }

        let r = self.buf[0..*value].to_owned();

        Box::pin(ready(Ok(Some(r))))
    }
}
impl Control for AsyncPipeStream {
    fn close(&mut self) -> crate::PinFutureLocal<'_, ()> {
        Box::pin(async move {
            self.output.shutdown().await?;
            Ok(())
        })
    }

    fn rx_closed(&self) -> bool {
        self.rx_shut
    }
}
