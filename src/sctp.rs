use crate::{
    pipe_stream::{Control, PipeStream, WaitThen},
    DynResult, PinFutureLocal,
};
use bytes::Bytes;
use futures::{
    future::{ready, Either},
    FutureExt,
};
use std::{any::Any, sync::Arc, time::Duration};
use tokio::{select, time::sleep};
use webrtc_sctp::{
    association::Association, chunk::chunk_payload_data::PayloadProtocolIdentifier, stream::Stream,
};
use webrtc_util::Conn;

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

        let stream = match dialer {
            true => {
                association
                    .open_stream(1, PayloadProtocolIdentifier::Binary)
                    .await?
            }
            false => association
                .accept_stream()
                .await
                .ok_or_else(|| anyhow::anyhow!("Association closed when waiting for stream"))?,
        };
        stream.write_sctp(
            &Bytes::from_static(b"\0"),
            PayloadProtocolIdentifier::StringEmpty,
        )?;
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
            self.stream
                .write_sctp(&data.to_owned().into(), PayloadProtocolIdentifier::Binary)?;
            while self.stream.buffered_amount() > 4 * 1024 * 1024 {
                sleep(Duration::from_millis(100)).await;
            }

            Ok(())
        })
    }
}
impl WaitThen for Sctp {
    type Value = Either<Box<dyn Any>, (usize, PayloadProtocolIdentifier)>;
    type Output = Option<Vec<u8>>;

    fn wait(&mut self) -> PinFutureLocal<'_, Self::Value> {
        self.buf.resize(8096, 0);

        Box::pin(async move {
            let r = select! {
                value = self.underlying.wait_dyn() => {
                    Either::Left(value?)
                },
                r = self.stream.read_sctp(&mut self.buf[..]) => {
                    let (n, protocol_id) = r?;
                    Either::Right((n, protocol_id))
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
            Either::Right((n, protocol_id)) => {
                if *protocol_id != PayloadProtocolIdentifier::Binary {
                    return ready(Ok(None)).boxed();
                }

                let r = self.buf[0..*n].to_owned();
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
            self.stream.shutdown(std::net::Shutdown::Both).await?;

            Ok(())
        })
    }

    fn rx_closed(&self) -> bool {
        self.underlying.rx_closed()
    }
}
