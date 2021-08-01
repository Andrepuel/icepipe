#![feature(backtrace)]

pub mod agreement;
pub mod constants;
pub mod crypto_stream;
pub mod ice;
pub mod pipe_stream;
pub mod sctp;
pub mod signalling;
pub mod stdio;
pub mod ws;

use std::{future::Future, pin::Pin, process};

use signalling::Signalling;
use tokio::select;

use crate::{
    agreement::Agreement,
    crypto_stream::Chacha20Stream,
    ice::IceAgent,
    pipe_stream::{Control, PipeStream, WaitThen},
    sctp::Sctp,
    stdio::Stdio,
    ws::Websocket,
};

type DynResult<T> = Result<T, anyhow::Error>;
type PinFuture<'a, T> = Pin<Box<dyn Future<Output = DynResult<T>> + Send + 'a>>;
type PinFutureLocal<'a, T> = Pin<Box<dyn Future<Output = DynResult<T>> + 'a>>;

#[tokio::main]
async fn main() -> DynResult<()> {
    env_logger::init();

    main2().await
}

async fn main2() -> DynResult<()> {
    let url = url::Url::parse(&constants::signalling_server()?)?;
    let base_password = std::env::args()
        .nth(1)
        .ok_or(anyhow::anyhow!("Missing channel for signalling"))?;
    let channel = Agreement::<Websocket>::derive_text(&base_password, true, "channel");
    let url = url.join(&channel).unwrap();

    let (signalling, dialer) = Websocket::new(url).await?;
    let agreement = Agreement::new(signalling, base_password, dialer);
    let (basekey, signalling) = agreement.agree().await?;

    let mut agent = IceAgent::new(signalling, dialer, constants::ice_urls()?).await?;
    let net_conn = agent.connect().await?;
    let stream = Sctp::new(net_conn, dialer, agent).await?;
    let mut stream = Chacha20Stream::new(&basekey, dialer, stream)?;
    let mut stdio = Stdio::new();

    while !stream.rx_closed() && !stdio.rx_closed() {
        select! {
            value = stream.wait() => {
                let recv = stream.then(&mut value?).await?;
                if let Some(data) = recv {
                    stdio.send(&data).await?;
                }
            }
            value = stdio.wait() => {
                let recv = stdio.then(&mut value?).await?;
                if let Some(data) = recv {
                    stream.send(&data).await?;
                }
            },
        }
    }
    stream.close().await?;
    stdio.close().await?;

    process::exit(0);
}
