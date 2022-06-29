use crate::{
    pipe_stream::{Consume, WaitThen},
    signalling::Signalling,
    DynResult,
};
use futures::{future::Either, SinkExt, StreamExt};
use std::time::{Duration, Instant};
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
    pub async fn new(url: Url) -> DynResult<(Websocket, bool)> {
        let (mut ws, _) = connect_async(url).await?;
        let peer_type = ws
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("Closed socket"))??;

        let dialer = match peer_type {
            Message::Text(msg) => {
                log::info!("User type {:?}", msg);
                msg == "DIALER"
            }
            x => Err(anyhow::anyhow!("Unexpected peer type msg {:?}", x))?,
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
    fn send(&mut self, msg: String) -> crate::PinFuture<'_, ()> {
        Box::pin(async move {
            self.ws.send(Message::Text(msg)).await?;

            Ok(())
        })
    }
}

impl WaitThen for Websocket {
    type Value = Either<Message, ()>;
    type Output = Option<String>;

    fn wait(&mut self) -> crate::PinFutureLocal<'_, Self::Value> {
        let next_ping = self.last_ping + Duration::from_secs(15);
        let pong_timeout = self.last_pong + Duration::from_secs(60);
        Box::pin(async move {
            select! {
                msg = self.ws.next() => {
                    let msg = msg.ok_or_else(|| anyhow::anyhow!("Closed signalling"))??;
                    Ok(Either::Left(msg))
                },
                _ = sleep_until(next_ping.into()) => {
                    Ok(Either::Right(()))
                }
                _ = sleep_until(pong_timeout.into()) => {
                    Err(anyhow::anyhow!("Ping timeout"))
                }
            }
        })
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> crate::PinFutureLocal<'a, Self::Output> {
        Box::pin(async move {
            match value {
                Either::Left(msg) => {
                    let msg = msg.consume(Message::Text(Default::default()));
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
                        x => Err(anyhow::anyhow!("Unexpected signalling {:?}", x))?,
                    };

                    Ok(Some(candidate))
                }
                Either::Right(_) => {
                    self.last_ping = Instant::now();
                    self.ws.send(Message::Ping(vec![])).await?;
                    Ok(None)
                }
            }
        })
    }
}
