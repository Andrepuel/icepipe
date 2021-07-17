use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use url::Url;

use crate::{DynResult, Signalling};

pub struct Websocket {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}
unsafe impl Send for Websocket {}
impl Websocket {
    pub async fn new(url: Url) -> DynResult<(Websocket, bool)> {
        let (mut ws, _) = connect_async(url).await?;
        let peer_type = ws.next().await.ok_or(anyhow::anyhow!("Closed socket"))??;

        let dialer = match peer_type {
            Message::Text(msg) => {
                eprintln!("User type {:?}", msg);
                msg == "DIALER"
            }
            x => Err(anyhow::anyhow!("Unexpected peer type msg {:?}", x))?,
        };

        Ok((Websocket { ws }, dialer))
    }
}
impl Signalling for Websocket {
    fn send(&mut self, msg: String) -> crate::PinFuture<'_, ()> {
        Box::pin(async move {
            self.ws.send(Message::Text(msg)).await?;

            Ok(())
        })
    }

    fn recv(&mut self) -> crate::PinFuture<'_, String> {
        Box::pin(async move {
            let msg = self
                .ws
                .next()
                .await
                .ok_or(anyhow::anyhow!("Closed signalling"))??;
            let candidate = match msg {
                Message::Text(candidate) => candidate,
                x => Err(anyhow::anyhow!("Unexpected signalling {:?}", x))?,
            };

            Ok(candidate)
        })
    }
}
