#![feature(backtrace)]

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::{sync::mpsc, time::sleep};
use webrtc_ice::{
    agent::{agent_config::AgentConfig, Agent},
    candidate::Candidate,
    url::Url,
};
use webrtc_util::Conn;

type DynResult<T> = Result<T, anyhow::Error>;
type PinFuture<'a, T> = Pin<Box<dyn Future<Output = DynResult<T>> + Send + 'a>>;

trait Signalling {
    fn send(&self, candidates: Vec<String>) -> PinFuture<'static, ()>;
    fn recv(&self) -> PinFuture<'static, Vec<String>>;
    fn clone(&self) -> Box<dyn Signalling>;
}

#[derive(Clone)]
pub struct FileSignalling {
    recv_path: String,
    send_path: String,
}
impl FileSignalling {
    pub fn dial(base: &str) -> FileSignalling {
        FileSignalling {
            recv_path: format!("{}_dial", base),
            send_path: format!("{}_accept", base),
        }
    }

    pub fn accept(base: &str) -> FileSignalling {
        FileSignalling {
            recv_path: format!("{}_accept", base),
            send_path: format!("{}_dial", base),
        }
    }
}
impl Signalling for FileSignalling {
    fn send(&self, candidates: Vec<String>) -> PinFuture<'static, ()> {
        eprintln!("sent {:?}", candidates);
        let send_path = self.send_path.clone();

        Box::pin(async move {
            tokio::fs::write(
                &send_path,
                candidates
                    .into_iter()
                    .fold(String::new(), |a, b| format!("{},{}", a, b)),
            )
            .await?;

            Ok(())
        })
    }

    fn recv(&self) -> PinFuture<'static, Vec<String>> {
        let recv_path = self.recv_path.clone();

        Box::pin(async move {
            let candidates = loop {
                if !std::path::Path::new(&recv_path).exists() {
                    eprintln!("{} does not exists, polling", recv_path);
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }

                break tokio::fs::read(&recv_path).await?;
            };
            std::fs::remove_file(&recv_path)?;
            let candidates = String::from_utf8(candidates)?;

            Ok(candidates
                .split(",")
                .filter(|x| x.len() > 0)
                .map(|x| x.to_string())
                .collect())
        })
    }

    fn clone(&self) -> Box<dyn Signalling> {
        Box::new(Clone::clone(self))
    }
}

#[tokio::main]
async fn main() -> DynResult<()> {
    main2().await
}

async fn main2() -> DynResult<()> {
    let (dialer, signalling, local, remote) = {
        match std::env::args().nth(1).as_ref().map(|x| x.as_str()) {
            Some("--dial") => {
                let signalling: Box<dyn Signalling + Send + Sync> =
                    Box::new(FileSignalling::dial(&std::env::args().nth(2).unwrap()));
                (
                    true,
                    signalling,
                    "locallocallocallocal",
                    "remoteremoteremoteremote",
                )
            }
            Some("--accept") => {
                let signalling: Box<dyn Signalling + Send + Sync> =
                    Box::new(FileSignalling::accept(&std::env::args().nth(2).unwrap()));
                (
                    false,
                    signalling,
                    "remoteremoteremoteremote",
                    "locallocallocallocal",
                )
            }
            _ => {
                eprintln!(
                    "Usage: {} --dial|--acept <base>",
                    std::env::args().nth(0).unwrap()
                );
                panic!();
            }
        }
    };

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

    let signalling2 = signalling.clone();
    let mut candidates = Vec::new();
    agent
        .on_candidate(Box::new(move |c| {
            if c.is_none() {
                let send = signalling.send(candidates.clone());
                return Box::pin(async move {
                    send.await.unwrap();

                    ()
                });
            }

            let c = c.unwrap();
            candidates.push(c.marshal());

            Box::pin(async move {})
        }))
        .await;
    eprintln!("on candidate set");

    agent.gather_candidates().await?;
    eprintln!("gather candidates started");

    eprintln!("Waiting peer candidates");
    for candidate in signalling2.recv().await? {
        let candidate: Arc<dyn Candidate + Send + Sync> =
            Arc::new(agent.unmarshal_remote_candidate(candidate).await?);
        agent.add_remote_candidate(&candidate).await?;
    }
    eprintln!("Connecting...");

    let cancel = mpsc::channel(1);
    let conn: Arc<dyn Conn> = match dialer {
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
    eprintln!("conn done");
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
