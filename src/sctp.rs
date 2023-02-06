use crate::{
    pipe_stream::{Control, PipeStream, WaitThen},
    IntoIoError,
};
use bytes::Bytes;
use futures::{
    future::{ready, Either, LocalBoxFuture},
    FutureExt,
};
use std::{io, sync::Arc, time::Duration};
use tokio::{select, time::sleep};
use webrtc_sctp::{
    association::Association, chunk::chunk_payload_data::PayloadProtocolIdentifier, stream::Stream,
};
use webrtc_util::Conn;

pub struct Sctp<C: Control> {
    _association: Association,
    stream: Arc<Stream>,
    buf: Vec<u8>,
    underlying: C,
}
impl<C: Control> Sctp<C> {
    pub async fn new(
        net_conn: Arc<dyn Conn + Send + Sync>,
        dialer: bool,
        underlying: C,
    ) -> SctpResult<Self, C::Error> {
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
                .ok_or(SctpError::AssociationClosedWithoutStream)?,
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
impl<C: Control> PipeStream for Sctp<C> {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> LocalBoxFuture<'a, SctpResult<(), C::Error>> {
        async move {
            self.stream
                .write_sctp(&data.to_owned().into(), PayloadProtocolIdentifier::Binary)?;
            while self.stream.buffered_amount() > 4 * 1024 * 1024 {
                sleep(Duration::from_millis(100)).await;
            }

            Ok(())
        }
        .boxed_local()
    }
}
impl<C: Control> WaitThen for Sctp<C> {
    type Value = Either<C::Value, (usize, PayloadProtocolIdentifier)>;
    type Output = Option<Vec<u8>>;
    type Error = SctpError<C::Error>;

    fn wait(&mut self) -> LocalBoxFuture<'_, SctpResult<Self::Value, C::Error>> {
        self.buf.resize(8096, 0);

        Box::pin(async move {
            let r = select! {
                value = self.underlying.wait() => {
                    Either::Left(value.map_err(SctpError::ControlError)?)
                },
                r = self.stream.read_sctp(&mut self.buf[..]) => {
                    let (n, protocol_id) = r?;
                    Either::Right((n, protocol_id))
                }
            };
            Ok(r)
        })
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> LocalBoxFuture<'a, SctpResult<Self::Output, C::Error>> {
        match value {
            Either::Left(x) => {
                let r = self.underlying.then(x);
                Box::pin(async move {
                    r.await.map_err(SctpError::ControlError)?;
                    Ok(None)
                })
            }
            Either::Right((n, protocol_id)) => {
                if *protocol_id != PayloadProtocolIdentifier::Binary {
                    return ready(Ok(None)).boxed_local();
                }

                let r = self.buf[0..*n].to_owned();
                Box::pin(ready(Ok(Some(r))))
            }
        }
    }
}
impl<C: Control> Control for Sctp<C> {
    fn close(&mut self) -> LocalBoxFuture<'_, SctpResult<(), C::Error>> {
        async move {
            while self.stream.buffered_amount() > 0 {
                sleep(Duration::from_millis(100)).await;
            }
            sleep(Duration::from_millis(100)).await;

            self.underlying
                .close()
                .await
                .map_err(SctpError::ControlError)?;
            self.stream.shutdown(std::net::Shutdown::Both).await?;

            Ok(())
        }
        .boxed_local()
    }

    fn rx_closed(&self) -> bool {
        self.underlying.rx_closed()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SctpError<E: std::error::Error> {
    #[error(transparent)]
    ControlError(E),
    #[error("Association closed when waiting for stream")]
    AssociationClosedWithoutStream,
    #[error(transparent)]
    WebrtcSctpError(#[from] webrtc_sctp::Error),
}
impl<E: std::error::Error + IntoIoError> IntoIoError for SctpError<E> {
    fn kind(&self) -> io::ErrorKind {
        match self {
            SctpError::ControlError(e) => e.kind(),
            SctpError::AssociationClosedWithoutStream => io::ErrorKind::ConnectionReset,
            SctpError::WebrtcSctpError(_) => io::ErrorKind::Other,
        }
    }
}
impl<E: std::error::Error + IntoIoError> From<SctpError<E>> for io::Error {
    fn from(value: SctpError<E>) -> Self {
        match value {
            SctpError::ControlError(e) => e.into(),
            e => io::Error::new(e.kind(), e),
        }
    }
}

pub type SctpResult<T, E> = Result<T, SctpError<E>>;
