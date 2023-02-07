use crate::{
    error::TimeoutError,
    pipe_stream::WaitThen,
    signalling::{SignalingError, Signalling},
};
use futures::{future::LocalBoxFuture, FutureExt, SinkExt, StreamExt};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, select, time::sleep_until};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use url::Url;

pub struct Websocket {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    last_ping: Instant,
    last_pong: Instant,
}
unsafe impl Send for Websocket {}
impl Websocket {
    pub async fn new(url: Url) -> WebsocketResult<(Self, bool)> {
        let (mut ws, _) = connect_async(url).await?;
        let peer_type = ws
            .next()
            .await
            .ok_or(TungsteniteError::ConnectionClosed)??;

        let dialer = match peer_type {
            Message::Text(msg) => {
                log::info!("User type {:?}", msg);
                msg == "DIALER"
            }
            x => {
                return Err(ProtocolError::Unexpected(
                    x,
                    Expected::MessageText("DIALER or LISTENER"),
                ))?
            }
        };

        let last_ping = Instant::now();
        let last_pong = Instant::now();

        Ok((
            Websocket {
                ws,
                last_ping,
                last_pong,
            },
            dialer,
        ))
    }
}
impl Signalling for Websocket {
    fn send(&mut self, msg: String) -> LocalBoxFuture<WebsocketResult<()>> {
        Box::pin(async move {
            self.ws.send(Message::Text(msg)).await?;

            Ok(())
        })
    }
}
impl WaitThen for Websocket {
    type Value = WebsocketValue;
    type Output = Option<String>;
    type Error = WebsocketError;

    fn wait(&mut self) -> LocalBoxFuture<'_, WebsocketResult<Self::Value>> {
        let next_ping = self.last_ping + Duration::from_secs(15);
        let pong_timeout = self.last_pong + Duration::from_secs(60);
        async move {
            select! {
                msg = self.ws.next() => {
                    let msg = msg.ok_or(TungsteniteError::ConnectionClosed)??;
                    Ok(WebsocketValue::Incoming(msg))
                },
                _ = sleep_until(next_ping.into()) => {
                    Ok(WebsocketValue::Ping)
                }
                _ = sleep_until(pong_timeout.into()) => {
                    Err(TimeoutError.into())
                }
            }
        }
        .boxed_local()
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> LocalBoxFuture<'a, WebsocketResult<Self::Output>> {
        async move {
            match value {
                WebsocketValue::Incoming(msg) => {
                    let msg = std::mem::replace(msg, Message::Text(Default::default()));
                    let candidate = match msg {
                        Message::Text(candidate) => candidate,
                        Message::Ping(a) => {
                            self.last_ping = Instant::now();
                            self.last_pong = Instant::now();
                            self.ws.send(Message::Pong(a)).await?;
                            return Ok(None);
                        }
                        Message::Pong(_) => {
                            self.last_ping = Instant::now();
                            self.last_pong = Instant::now();
                            return Ok(None);
                        }
                        x => {
                            return Err(
                                ProtocolError::Unexpected(x, Expected::MessageTextOrPong).into()
                            )
                        }
                    };

                    Ok(Some(candidate))
                }
                WebsocketValue::Ping => {
                    self.last_ping = Instant::now();
                    self.ws.send(Message::Ping(vec![])).await?;
                    Ok(None)
                }
            }
        }
        .boxed_local()
    }
}
pub enum WebsocketValue {
    Incoming(Message),
    Ping,
}

#[derive(thiserror::Error, Debug)]
pub enum WebsocketError {
    #[error("Protocol level error: {0}")]
    ProtocolError(#[from] ProtocolError),
    #[error(transparent)]
    WebsocketError(#[from] TungsteniteError),
    #[error("Ping timeout")]
    Timeout(#[from] TimeoutError),
}
impl From<WebsocketError> for SignalingError {
    fn from(value: WebsocketError) -> Self {
        match value {
            WebsocketError::ProtocolError(e) => e.into(),
            WebsocketError::WebsocketError(e) => e.into(),
            WebsocketError::Timeout(e) => e.into(),
        }
    }
}
pub type WebsocketResult<T> = Result<T, WebsocketError>;
pub type TungsteniteError = tokio_tungstenite::tungstenite::Error;
impl From<TungsteniteError> for SignalingError {
    fn from(value: TungsteniteError) -> Self {
        match value {
            e @ TungsteniteError::ConnectionClosed => {
                io::Error::new(io::ErrorKind::ConnectionReset, e).into()
            }
            e @ TungsteniteError::AlreadyClosed => {
                io::Error::new(io::ErrorKind::ConnectionReset, e).into()
            }
            TungsteniteError::Io(e) => e.into(),
            e @ TungsteniteError::Tls(_) => io::Error::new(io::ErrorKind::Other, e).into(),
            e @ TungsteniteError::Capacity(_) => {
                io::Error::new(io::ErrorKind::OutOfMemory, e).into()
            }
            e @ TungsteniteError::Protocol(_) => SignalingError::ProtocolError(Box::new(e)),
            e @ TungsteniteError::SendQueueFull(_) => {
                io::Error::new(io::ErrorKind::OutOfMemory, e).into()
            }
            e @ TungsteniteError::Utf8 => io::Error::new(io::ErrorKind::InvalidData, e).into(),
            e @ TungsteniteError::Url(_) => io::Error::new(io::ErrorKind::InvalidInput, e).into(),
            e @ TungsteniteError::Http(_) => io::Error::new(io::ErrorKind::InvalidData, e).into(),
            e @ TungsteniteError::HttpFormat(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e).into()
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("Expected {0:?} but got {0:?}")]
    Unexpected(Message, Expected),
}
impl From<ProtocolError> for SignalingError {
    fn from(value: ProtocolError) -> Self {
        SignalingError::ProtocolError(Box::new(value))
    }
}

#[derive(Debug)]
pub enum Expected {
    MessageText(&'static str),
    MessageTextOrPong,
}
impl std::fmt::Display for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expected::MessageText(desc) => write!(f, "Text Message with {desc}"),
            Expected::MessageTextOrPong => write!(f, "Text Message or Pong"),
        }
    }
}
