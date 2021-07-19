#![feature(backtrace)]

pub mod ice;
pub mod pipe_stream;
pub mod sctp;
pub mod signalling;
pub mod stdio;
pub mod ws;

use std::{future::Future, pin::Pin, process};

use anyhow::Context;

use signalling::Signalling;
use tokio::select;

use crate::{
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
    let (signalling, dialer) = Websocket::new(
        url::Url::parse(
            &std::env::args()
                .nth(1)
                .ok_or(anyhow::anyhow!("Missing URL for signalling"))?,
        )
        .context("Invalid provided URL")?,
    )
    .await?;

    let mut agent = IceAgent::new(signalling, dialer).await?;
    let net_conn = agent.connect().await?;
    let mut sctp = Sctp::new(net_conn, dialer, agent).await?;
    let mut stdio = Stdio::new();

    while !sctp.rx_closed() && !stdio.rx_closed() {
        select! {
            value = sctp.wait() => {
                let recv = sctp.then(&mut value?).await?;
                if let Some(data) = recv {
                    stdio.send(&data).await?;
                }
            }
            value = stdio.wait() => {
                let recv = stdio.then(&mut value?).await?;
                if let Some(data) = recv {
                    sctp.send(&data).await?;
                }
            },
        }
    }
    sctp.close().await?;
    stdio.close().await?;

    process::exit(0);
}
