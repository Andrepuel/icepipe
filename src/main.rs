#![feature(backtrace)]

pub mod ws;

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::Context;
use tokio::{select, sync::mpsc};
use webrtc_ice::{
    agent::{agent_config::AgentConfig, Agent},
    candidate::Candidate,
    url::Url,
};
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
    main2().await
}

async fn main2() -> DynResult<()> {
    let (mut signalling, dialer) = Websocket::new(
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

    let agent = Agent::new(cfg).await?;

    let (candidates_tx_producer, mut candidates_tx) = mpsc::channel(1);
    agent
        .on_candidate(Box::new(move |c| {
            let send = candidates_tx_producer.clone();
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
    ) -> DynResult<Arc<dyn Conn>> {
        let cancel = mpsc::channel(1);
        let r: Arc<dyn Conn> = match dialer {
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
    let conn = loop {
        let conn_ing = &mut conn_ing;
        select! {
            conn = conn_ing => {
                break conn?;
            },
            candidate = candidates_tx.recv() => {
                let candidate = candidate.ok_or(anyhow::anyhow!("Candidates channel closed?"))?;
                eprintln!("TX candidate {}", candidate);
                signalling.send(candidate).await?;
            }
            candidate = signalling.recv() => {
                let candidate = candidate?;
                eprintln!("RX candidate {}", candidate);
                let candidate: Arc<dyn Candidate + Send + Sync> =
                    Arc::new(agent.unmarshal_remote_candidate(candidate).await?);
                agent.add_remote_candidate(&candidate).await?;
            }
        }
    };

    conn.send(b"each").await?;
    let mut buf = Vec::new();
    {
        buf.resize(1024, 0);
        let n = conn.recv(&mut buf).await?;
        buf.resize(n, 0);
    }
    eprintln!("RX {:?}", buf);

    Ok(())
}
