#![feature(backtrace)]

pub mod ws;

use std::{future::Future, pin::Pin, process, sync::Arc, time::Duration};

use anyhow::Context;
use futures_util::future::Either;
use tokio::{
    io::{stdin, stdout, AsyncReadExt, AsyncWriteExt},
    select,
    sync::mpsc,
    time::sleep,
};
use webrtc_ice::{
    agent::{agent_config::AgentConfig, Agent},
    candidate::Candidate,
    url::Url,
};
use webrtc_sctp::{association::Association, chunk::chunk_payload_data::PayloadProtocolIdentifier};
use webrtc_util::Conn;

use crate::ws::Websocket;

type DynResult<T> = Result<T, anyhow::Error>;
type PinFuture<'a, T> = Pin<Box<dyn Future<Output = DynResult<T>> + Send + 'a>>;

pub trait Signalling {
    fn send(&mut self, candidates: String) -> PinFuture<'_, ()>;
    fn recv(&mut self) -> PinFuture<'_, String>;
}

#[tokio::main]
async fn main() -> DynResult<()> {
    env_logger::init();

    main2().await
}

struct CandidateExchange<'a> {
    agent: &'a Agent,
    candidate_rx: mpsc::Receiver<String>,
    signalling: Box<dyn Signalling>,
    tx_shut: bool,
    rx_shut: bool,
}
impl<'a> CandidateExchange<'a> {
    fn new<T: Signalling + 'static>(
        agent: &'a Agent,
        signalling: T,
    ) -> (CandidateExchange<'a>, mpsc::Sender<String>) {
        let (candidate_tx, candidate_rx) = mpsc::channel(1);
        let signalling = Box::new(signalling);

        (
            CandidateExchange {
                agent,
                candidate_rx,
                signalling,
                tx_shut: false,
                rx_shut: false,
            },
            candidate_tx,
        )
    }

    async fn close(&mut self) -> DynResult<()> {
        if !self.tx_shut {
            self.signalling.send("Close".to_string()).await?;
            self.tx_shut = true;
        }

        Ok(())
    }

    async fn wait(&mut self) -> DynResult<Either<String, String>> {
        select! {
            candidate = self.candidate_rx.recv() => {
                Ok(Either::Left(candidate.ok_or(anyhow::anyhow!("Candidates channel closed?"))?))
            }
            candidate = self.signalling.recv() => {
                Ok(Either::Right(candidate?))
            }
        }
    }

    async fn then(&mut self, value: Either<String, String>) -> DynResult<()> {
        match value {
            Either::Left(candidate) => {
                log::info!("TX candidate {}", candidate);
                self.signalling.send(candidate).await?;
            }
            Either::Right(x) if x == "Close" => {
                log::info!("RX shutdown");
                self.rx_shut = true;
            }
            Either::Right(candidate) => {
                log::info!("RX candidate {}", candidate);
                let candidate: Arc<dyn Candidate + Send + Sync> =
                    Arc::new(self.agent.unmarshal_remote_candidate(candidate).await?);
                self.agent.add_remote_candidate(&candidate).await?;
            }
        }

        Ok(())
    }
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

    let local;
    let remote;

    if dialer {
        local = "locallocallocallocal";
        remote = "remoteremoteremoteremote";
    } else {
        local = "remoteremoteremoteremote";
        remote = "locallocallocallocal";
    }

    let mut cfg = AgentConfig::default();
    cfg.local_pwd = local.to_string();
    cfg.local_ufrag = local.to_string();
    cfg.network_types
        .push(webrtc_ice::network_type::NetworkType::Udp4);
    cfg.network_types
        .push(webrtc_ice::network_type::NetworkType::Udp6);
    cfg.urls
        .push(Url::parse_url("stun:stun.l.google.com:19302")?);
    cfg.disconnected_timeout = None;

    let agent = Agent::new(cfg).await?;
    let (mut candidate_exchange, candidates_tx) = CandidateExchange::new(&agent, signalling);
    agent
        .on_candidate(Box::new(move |c| {
            let send = candidates_tx.clone();
            Box::pin(async move {
                if let Some(c) = c {
                    send.send(c.marshal()).await.unwrap();
                }
            })
        }))
        .await;
    agent.gather_candidates().await?;

    async fn connect(
        agent: &Agent,
        dialer: bool,
        remote: &'static str,
    ) -> DynResult<Arc<dyn Conn + Send + Sync>> {
        let cancel = mpsc::channel(1);
        let r: Arc<dyn Conn + Send + Sync> = match dialer {
            true => {
                agent
                    .dial(cancel.1, remote.to_string(), remote.to_string())
                    .await?
            }
            false => {
                agent
                    .accept(cancel.1, remote.to_string(), remote.to_string())
                    .await?
            }
        };
        Ok(r)
    }

    let mut conn_ing = Box::pin(connect(&agent, dialer, remote));
    let net_conn = loop {
        let conn_ing = &mut conn_ing;
        select! {
            conn = conn_ing => {
                break conn?;
            },
            value = candidate_exchange.wait() => {
                candidate_exchange.then(value?).await?;
            }
        }
    };
    log::info!("ICE connected");

    let config = webrtc_sctp::association::Config {
        net_conn,
        max_receive_buffer_size: 4 * 1024 * 1024,
        max_message_size: 4 * 1024,
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

    let mut stdin = stdin();
    let mut stdout = stdout();
    let mut tx_buf = Vec::new();
    let mut rx_buf = Vec::new();

    while !candidate_exchange.rx_shut {
        tx_buf.resize(4096, 0);
        rx_buf.resize(4096, 0);

        select! {
            value = candidate_exchange.wait() => {
                candidate_exchange.then(value?).await?;
            }
            n = stdin.read(&mut tx_buf) => {
                let n  = n?;
                if n == 0 {
                    break;
                }
                tx_buf.resize(n, 0);
                while stream.buffered_amount() > 4096*1024 {
                    sleep(Duration::from_millis(100)).await;
                }
                let n = stream.write(&tx_buf.clone().into()).await?;
                assert_eq!(n, tx_buf.len());
            },
            n = stream.read(&mut rx_buf) => {
                let n = n?;
                rx_buf.resize(n, 0);
                stdout.write_all(&rx_buf).await?;
            },
        }
    }
    while stream.buffered_amount() > 0 {
        sleep(Duration::from_millis(100)).await;
    }
    sleep(Duration::from_millis(100)).await;
    candidate_exchange.close().await?;
    while !candidate_exchange.rx_shut {
        let v = candidate_exchange.wait().await?;
        candidate_exchange.then(v).await?;
    }
    stdout.flush().await?;
    drop(stdout);

    process::exit(0);
}
