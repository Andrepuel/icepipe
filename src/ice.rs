use crate::{
    pipe_stream::{Control, WaitThen, WaitThenDynExt},
    signalling::Signalling,
    DynResult, PinFutureLocal,
};
use futures::future::Either;
use std::{any::Any, sync::Arc};
use tokio::{select, sync::mpsc};
use webrtc_ice::{
    agent::{agent_config::AgentConfig, Agent},
    candidate::{candidate_base::unmarshal_candidate, Candidate},
    url::Url,
};
use webrtc_util::Conn;

type CandidateExchangeValue = Either<String, Box<dyn Any>>;
pub struct CandidateExchange {
    candidate_rx: mpsc::Receiver<String>,
    signalling: Box<dyn Signalling>,
    tx_shut: bool,
    rx_shut: bool,
}
impl CandidateExchange {
    pub async fn new<T: Signalling + 'static>(
        mut signalling: T,
    ) -> DynResult<(CandidateExchange, mpsc::Sender<String>)> {
        let handshake = "Icepipe";

        signalling.send(handshake.into()).await?;
        let recv = loop {
            match signalling.recv().await? {
                Some(x) => break x,
                None => continue,
            }
        };
        if recv != handshake {
            return Err(anyhow::anyhow!(
                "Protocol errror, received: {:?}, expected {:?}",
                recv,
                handshake
            ));
        }

        let (candidate_tx, candidate_rx) = mpsc::channel(1);
        let signalling = Box::new(signalling);

        let r = (
            CandidateExchange {
                candidate_rx,
                signalling,
                tx_shut: false,
                rx_shut: false,
            },
            candidate_tx,
        );

        Ok(r)
    }

    pub async fn close(&mut self) -> DynResult<()> {
        if !self.tx_shut {
            log::info!("TX shutdown");
            self.signalling.send("Close".to_string()).await?;
            self.tx_shut = true;
        }

        while !self.rx_shut {
            let mut value = self.wait().await?;
            self.then(None, &mut value).await?;
        }

        Ok(())
    }

    pub async fn wait(&mut self) -> DynResult<CandidateExchangeValue> {
        select! {
            candidate = self.candidate_rx.recv() => {
                Ok(Either::Left(candidate.ok_or_else(||anyhow::anyhow!("Candidates channel closed?"))?))
            }
            candidate = self.signalling.wait_dyn() => {
                Ok(Either::Right(candidate?))
            }
        }
    }

    pub async fn then(
        &mut self,
        agent: Option<&Agent>,
        value: &mut CandidateExchangeValue,
    ) -> DynResult<()> {
        let value = std::mem::replace(value, Either::Left(Default::default()));
        match value {
            Either::Left(candidate) => {
                log::info!("TX candidate {}", candidate);
                self.signalling.send(candidate).await?;
            }
            Either::Right(mut value) => match self.signalling.then_dyn(&mut value).await? {
                None => {}
                Some(x) if x == "Close" => {
                    log::info!("RX shutdown");
                    self.rx_shut = true;
                }
                Some(candidate) => match agent {
                    Some(agent) => {
                        log::info!("RX candidate {}", candidate);
                        let candidate: Arc<dyn Candidate + Send + Sync> =
                            Arc::new(unmarshal_candidate(&candidate).await?);
                        agent.add_remote_candidate(&candidate).await?;
                    }
                    None => {
                        log::info!("RX candidate {} discarded", candidate);
                    }
                },
            },
        }

        Ok(())
    }
}

pub struct IceAgent {
    agent: Agent,
    exchange: CandidateExchange,
    dialer: bool,
}
impl IceAgent {
    fn get_local(dialer: bool) -> &'static str {
        if dialer {
            "locallocallocallocal"
        } else {
            "remoteremoteremoteremote"
        }
    }

    fn get_remote(dialer: bool) -> &'static str {
        if dialer {
            "remoteremoteremoteremote"
        } else {
            "locallocallocallocal"
        }
    }

    pub async fn new<T: Signalling + 'static>(
        signalling: T,
        dialer: bool,
        urls: Vec<Url>,
    ) -> DynResult<IceAgent> {
        let cfg = AgentConfig {
            local_pwd: Self::get_local(dialer).to_string(),
            local_ufrag: Self::get_local(dialer).to_string(),
            network_types: vec![
                webrtc_ice::network_type::NetworkType::Udp4,
                webrtc_ice::network_type::NetworkType::Udp6,
            ],
            urls,
            disconnected_timeout: None,
            ..AgentConfig::default()
        };

        let agent = Agent::new(cfg).await?;
        let (exchange, candidates_tx) = CandidateExchange::new(signalling).await?;
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

        Ok(IceAgent {
            agent,
            exchange,
            dialer,
        })
    }

    async fn wait2(exchange: &mut CandidateExchange) -> DynResult<<Self as WaitThen>::Value> {
        exchange.wait().await
    }

    async fn then2(
        agent: &Agent,
        exchange: &mut CandidateExchange,
        value: &mut <Self as WaitThen>::Value,
    ) -> DynResult<()> {
        exchange.then(Some(agent), value).await
    }

    pub async fn connect(&mut self) -> DynResult<Arc<dyn Conn + Send + Sync>> {
        async fn do_connect(agent: &Agent, dialer: bool) -> DynResult<Arc<dyn Conn + Send + Sync>> {
            let cancel = mpsc::channel(1);
            let r: Arc<dyn Conn + Send + Sync> = match dialer {
                true => {
                    agent
                        .dial(
                            cancel.1,
                            IceAgent::get_remote(dialer).to_string(),
                            IceAgent::get_remote(dialer).to_string(),
                        )
                        .await?
                }
                false => {
                    agent
                        .accept(
                            cancel.1,
                            IceAgent::get_remote(dialer).to_string(),
                            IceAgent::get_remote(dialer).to_string(),
                        )
                        .await?
                }
            };
            Ok(r)
        }

        let mut conn_ing = Box::pin(do_connect(&self.agent, self.dialer));
        let net_conn = loop {
            let conn_ing = &mut conn_ing;
            select! {
                conn = conn_ing => {
                    break conn?;
                },
                value = Self::wait2(&mut self.exchange) => {
                    Self::then2(&self.agent, &mut self.exchange, &mut value?).await?;
                }
            }
        };
        log::info!("ICE connected");

        Ok(net_conn)
    }
}
impl WaitThen for IceAgent {
    type Value = CandidateExchangeValue;
    type Output = ();

    fn wait(&mut self) -> PinFutureLocal<'_, Self::Value> {
        Box::pin(async move { Self::wait2(&mut self.exchange).await })
    }

    fn then<'a>(&'a mut self, value: &'a mut Self::Value) -> PinFutureLocal<'a, Self::Output> {
        Box::pin(async move { Self::then2(&self.agent, &mut self.exchange, value).await })
    }
}
impl Control for IceAgent {
    fn close(&mut self) -> PinFutureLocal<'_, ()> {
        Box::pin(async move {
            self.exchange.close().await?;
            Ok(())
        })
    }

    fn rx_closed(&self) -> bool {
        self.exchange.rx_shut
    }
}
