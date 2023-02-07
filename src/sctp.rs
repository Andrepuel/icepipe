use crate::{
    error::TimeoutError,
    pipe_stream::{Control, PipeStream, StreamError, WaitThen},
    signalling::SignalingError,
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

pub struct Sctp<C>
where
    C: Control,
    C::Error: Into<StreamError>,
{
    _association: Association,
    stream: Arc<Stream>,
    buf: Vec<u8>,
    underlying: C,
}
impl<C> Sctp<C>
where
    C: Control,
    C::Error: Into<StreamError>,
{
    pub async fn new(
        net_conn: Arc<dyn Conn + Send + Sync>,
        dialer: bool,
        underlying: C,
    ) -> SctpResult<Self> {
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
impl<C> PipeStream for Sctp<C>
where
    C: Control,
    C::Error: Into<StreamError>,
{
    fn send<'a>(&'a mut self, data: &'a [u8]) -> LocalBoxFuture<'a, SctpResult<()>> {
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
impl<C> WaitThen for Sctp<C>
where
    C: Control,
    C::Error: Into<StreamError>,
{
    type Value = Either<C::Value, (usize, PayloadProtocolIdentifier)>;
    type Output = Option<Vec<u8>>;
    type Error = SctpError;

    fn wait(&mut self) -> LocalBoxFuture<'_, SctpResult<Self::Value>> {
        self.buf.resize(8096, 0);

        Box::pin(async move {
            let r = select! {
                value = self.underlying.wait() => {
                    Either::Left(value.map_err(Into::into)?)
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
    ) -> LocalBoxFuture<'a, SctpResult<Self::Output>> {
        match value {
            Either::Left(x) => {
                let r = self.underlying.then(x);
                Box::pin(async move {
                    r.await.map_err(Into::into)?;
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
impl<C> Control for Sctp<C>
where
    C: Control,
    C::Error: Into<StreamError>,
{
    fn close(&mut self) -> LocalBoxFuture<'_, SctpResult<()>> {
        async move {
            while self.stream.buffered_amount() > 0 {
                sleep(Duration::from_millis(100)).await;
            }
            sleep(Duration::from_millis(100)).await;

            self.underlying.close().await.map_err(Into::into)?;
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
pub enum SctpError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    SignalingError(SignalingError),
    #[error(transparent)]
    StreamError(StreamError),
    #[error("Association closed when waiting for stream")]
    AssociationClosedWithoutStream,
    #[error(transparent)]
    WebrtcSctpError(#[from] webrtc_sctp::Error),
}
impl From<SignalingError> for SctpError {
    fn from(value: SignalingError) -> Self {
        match value {
            SignalingError::Io(e) => e.into(),
            SignalingError::Timeout(e) => e.into(),
            e => Self::SignalingError(e),
        }
    }
}
impl From<StreamError> for SctpError {
    fn from(value: StreamError) -> Self {
        match value {
            StreamError::Io(e) => e.into(),
            StreamError::Timeout(e) => e.into(),
            StreamError::SignalingError(e) => e.into(),
            e @ StreamError::Other(_) => Self::StreamError(e),
        }
    }
}
impl From<SctpError> for StreamError {
    fn from(value: SctpError) -> Self {
        match value {
            SctpError::Io(e) => e.into(),
            SctpError::Timeout(e) => e.into(),
            SctpError::SignalingError(e) => e.into(),
            SctpError::StreamError(e) => e,
            e @ SctpError::AssociationClosedWithoutStream => StreamError::Other(Box::new(e)),
            e @ SctpError::WebrtcSctpError(_) => StreamError::Other(Box::new(e)),
        }
    }
}
pub type SctpResult<T> = Result<T, SctpError>;
