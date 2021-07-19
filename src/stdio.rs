use futures_util::future::ready;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Stdin, Stdout};

use crate::pipe_stream::{Control, PipeStream, WaitThen};

pub struct Stdio {
    stdin: Stdin,
    stdout: Stdout,
    rx_shut: bool,
    buf: Vec<u8>,
}
impl Stdio {
    pub fn new() -> Stdio {
        Stdio {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
            rx_shut: false,
            buf: Vec::new(),
        }
    }
}
impl PipeStream for Stdio {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> crate::PinFutureLocal<'a, ()> {
        Box::pin(async move {
            self.stdout.write_all(data).await?;
            Ok(())
        })
    }
}
impl WaitThen for Stdio {
    type Value = usize;
    type Output = Option<Vec<u8>>;

    fn wait(&mut self) -> crate::PinFutureLocal<'_, Self::Value> {
        self.buf.resize(4096, 0);
        Box::pin(async move {
            let n = self.stdin.read(&mut self.buf).await?;
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
impl Control for Stdio {
    fn close(&mut self) -> crate::PinFutureLocal<'_, ()> {
        Box::pin(async move {
            self.stdout.shutdown().await?;
            Ok(())
        })
    }

    fn rx_closed(&self) -> bool {
        self.rx_shut
    }
}
