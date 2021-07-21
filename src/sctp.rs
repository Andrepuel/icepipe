use std::{any::Any, sync::Arc, time::Duration};

use futures_util::future::{ready, Either};
use tokio::{select, time::sleep};
use webrtc_sctp::{
    association::Association, chunk::chunk_payload_data::PayloadProtocolIdentifier, stream::Stream,
};
use webrtc_util::Conn;

use crate::{
    pipe_stream::{Control, PipeStream, WaitThen},
    DynResult, PinFutureLocal,
};

pub struct Sctp {
    _association: Association,
    stream: Arc<Stream>,
    buf: Vec<u8>,
    underlying: Box<dyn Control<Output = ()>>,
}
impl Sctp {
    pub async fn new<T: Control<Output = ()> + 'static>(
        net_conn: Arc<dyn Conn + Send + Sync>,
        dialer: bool,
        underlying: T,
    ) -> DynResult<Sctp> {
        Self::new_dyn(net_conn, dialer, Box::new(underlying)).await
    }

    pub async fn new_dyn(
        net_conn: Arc<dyn Conn + Send + Sync>,
        dialer: bool,
        underlying: Box<dyn Control<Output = ()>>,
    ) -> DynResult<Sctp> {
        let config = webrtc_sctp::association::Config {
            net_conn,
            max_receive_buffer_size: 4 * 1024 * 1024,
            max_message_size: 8 * 1024,
            name: "IcePipe".to_string(),
        };

        let association = match dialer {
            true => Association::client(config).await?,
            false => Association::server(config).await?,
        };

        let stream = association
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .await?;
        log::info!("Stream Connected");

        let buf = Vec::new();

        Ok(Sctp {
            _association: association,
            stream,
            buf,
            underlying,
        })
    }
}
impl PipeStream for Sctp {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> PinFutureLocal<'a, ()> {
        Box::pin(async move {
            self.stream.write(&data.to_owned().into()).await?;
            while self.stream.buffered_amount() > 4 * 1024 * 1024 {
                sleep(Duration::from_millis(100)).await;
            }

            Ok(())
        })
    }
}
impl WaitThen for Sctp {
    type Value = Either<Box<dyn Any>, usize>;
    type Output = Option<Vec<u8>>;

    fn wait(&mut self) -> PinFutureLocal<'_, Self::Value> {
        self.buf.resize(8096, 0);

        Box::pin(async move {
            let r = select! {
                value = self.underlying.wait_dyn() => {
                    Either::Left(value?)
                },
                n = self.stream.read(&mut self.buf[..]) => {
                    Either::Right(n?)
                }
            };
            Ok(r)
        })
    }

    fn then<'a>(&'a mut self, value: &'a mut Self::Value) -> PinFutureLocal<'a, Self::Output> {
        match value {
            Either::Left(x) => {
                let r = self.underlying.then_dyn(x);
                Box::pin(async move {
                    r.await?;
                    Ok(None)
                })
            }
            Either::Right(value) => {
                let r = self.buf[0..*value].to_owned();
                Box::pin(ready(Ok(Some(r))))
            }
        }
    }
}
impl Control for Sctp {
    fn close(&mut self) -> PinFutureLocal<'_, ()> {
        Box::pin(async move {
            while self.stream.buffered_amount() > 0 {
                sleep(Duration::from_millis(100)).await;
            }
            sleep(Duration::from_millis(100)).await;

            self.underlying.close().await?;
            self.stream.close().await?;

            Ok(())
        })
    }

    fn rx_closed(&self) -> bool {
        self.underlying.rx_closed()
    }
}
