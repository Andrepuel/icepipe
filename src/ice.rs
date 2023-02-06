use crate::{
    pipe_stream::{Control, WaitThen},
    signalling::Signalling,
    IntoIoError,
};
use futures::{
    future::{Either, LocalBoxFuture},
    pin_mut,
};
use std::{io, sync::Arc};
use tokio::{select, sync::mpsc};
use webrtc_ice::{
    agent::{agent_config::AgentConfig, Agent},
    candidate::{candidate_base::unmarshal_candidate, Candidate},
    url::Url,
};
use webrtc_util::Conn;

const PROTOCOL_START: &str = "Icepipe";
const PROTOCOL_CLOSE: &str = "Close";

type CandidateExchangeValue<S> = Either<String, <S as WaitThen>::Value>;
pub struct CandidateExchange<S: Signalling> {
    candidate_rx: mpsc::Receiver<String>,
    signalling: S,
    tx_shut: bool,
    rx_shut: bool,
}
impl<S: Signalling> CandidateExchange<S> {
    pub async fn new(mut signalling: S) -> IceResult<(Self, mpsc::Sender<String>), S::Error> {
        signalling
            .send(PROTOCOL_START.into())
            .await
            .map_err(IceError::SignalingError)?;
        let recv = loop {
            let mut value = signalling.wait().await.map_err(IceError::SignalingError)?;
            if let Some(recv) = signalling
                .then(&mut value)
                .await
                .map_err(IceError::SignalingError)?
            {
                break recv;
            }
        };

        if recv != PROTOCOL_START {
            return Err(IceError::BadHandshake(recv));
        }

        let (candidate_tx, candidate_rx) = mpsc::channel(1);

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

    pub async fn close(&mut self) -> IceResult<(), S::Error> {
        if !self.tx_shut {
            log::info!("TX shutdown");
            self.signalling
                .send(PROTOCOL_CLOSE.to_string())
                .await
                .map_err(IceError::SignalingError)?;
            self.tx_shut = true;
        }

        while !self.rx_shut {
            let mut value = self.wait().await?;
            self.then(None, &mut value).await?;
        }

        Ok(())
    }

    pub async fn wait(&mut self) -> IceResult<CandidateExchangeValue<S>, S::Error> {
        select! {
            candidate = self.candidate_rx.recv() => {
                let candidate = candidate.expect("Candidate channel closed on handler side");
                Ok(Either::Left(candidate))
            }
            candidate = self.signalling.wait() => {
                Ok(Either::Right(candidate.map_err(IceError::SignalingError)?))
            }
        }
    }

    pub async fn then(
        &mut self,
        agent: Option<&Agent>,
        value: &mut CandidateExchangeValue<S>,
    ) -> IceResult<(), S::Error> {
        let value = std::mem::replace(value, Either::Left(Default::default()));
        match value {
            Either::Left(candidate) => {
                log::info!("TX candidate {}", candidate);
                self.signalling
                    .send(candidate)
                    .await
                    .map_err(IceError::SignalingError)?;
            }
            Either::Right(mut value) => match self
                .signalling
                .then(&mut value)
                .await
                .map_err(IceError::SignalingError)?
                .as_deref()
            {
                None => {}
                Some(PROTOCOL_CLOSE) => {
                    log::info!("RX shutdown");
                    self.rx_shut = true;
                }
                Some(candidate) => match agent {
                    Some(agent) => {
                        log::info!("RX candidate {}", candidate);
                        let candidate: Arc<dyn Candidate + Send + Sync> =
                            Arc::new(unmarshal_candidate(candidate)?);
                        agent.add_remote_candidate(&candidate)?;
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

pub struct IceAgent<S: Signalling> {
    agent: Agent,
    exchange: CandidateExchange<S>,
    dialer: bool,
}
impl<S: Signalling> IceAgent<S> {
    pub async fn new(signalling: S, dialer: bool, urls: Vec<Url>) -> IceResult<Self, S::Error> {
        let cfg = AgentConfig {
            local_pwd: get_local(dialer).to_string(),
            local_ufrag: get_local(dialer).to_string(),
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
        agent.on_candidate(Box::new(move |c| {
            let send = candidates_tx.clone();
            Box::pin(async move {
                if let Some(c) = c {
                    send.send(c.marshal()).await.unwrap();
                }
            })
        }));

        agent.gather_candidates()?;

        Ok(IceAgent {
            agent,
            exchange,
            dialer,
        })
    }

    async fn wait2(
        exchange: &mut CandidateExchange<S>,
    ) -> IceResult<<Self as WaitThen>::Value, S::Error> {
        exchange.wait().await
    }

    async fn then2(
        agent: &Agent,
        exchange: &mut CandidateExchange<S>,
        value: &mut <Self as WaitThen>::Value,
    ) -> IceResult<(), S::Error> {
        exchange.then(Some(agent), value).await
    }

    pub async fn connect(&mut self) -> IceResult<Arc<dyn Conn + Send + Sync>, S::Error> {
        async fn do_connect(
            agent: &Agent,
            dialer: bool,
        ) -> Result<Arc<dyn Conn + Send + Sync>, webrtc_ice::Error> {
            let cancel = mpsc::channel(1);
            let r: Arc<dyn Conn + Send + Sync> = match dialer {
                true => {
                    agent
                        .dial(
                            cancel.1,
                            get_remote(dialer).to_string(),
                            get_remote(dialer).to_string(),
                        )
                        .await?
                }
                false => {
                    agent
                        .accept(
                            cancel.1,
                            get_remote(dialer).to_string(),
                            get_remote(dialer).to_string(),
                        )
                        .await?
                }
            };
            Ok(r)
        }

        let conn_ing = do_connect(&self.agent, self.dialer);
        pin_mut!(conn_ing);
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
impl<S: Signalling> WaitThen for IceAgent<S> {
    type Value = CandidateExchangeValue<S>;
    type Output = ();
    type Error = IceError<S::Error>;

    fn wait(&mut self) -> LocalBoxFuture<'_, IceResult<Self::Value, S::Error>> {
        Box::pin(async move { Self::wait2(&mut self.exchange).await })
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> LocalBoxFuture<'a, IceResult<Self::Output, S::Error>> {
        Box::pin(async move { Self::then2(&self.agent, &mut self.exchange, value).await })
    }
}
impl<S: Signalling> Control for IceAgent<S> {
    fn close(&mut self) -> LocalBoxFuture<'_, IceResult<(), S::Error>> {
        Box::pin(async move {
            self.exchange.close().await?;
            Ok(())
        })
    }

    fn rx_closed(&self) -> bool {
        self.exchange.rx_shut
    }
}

fn get_local(dialer: bool) -> &'static str {
    if dialer {
        "locallocallocallocal"
    } else {
        "remoteremoteremoteremote"
    }
}

fn get_remote(dialer: bool) -> &'static str {
    get_local(!dialer)
}

#[derive(thiserror::Error, Debug)]
pub enum IceError<E: std::error::Error> {
    #[error(transparent)]
    SignalingError(E),
    #[error("Bad handshake, expected {expected:?} but got {0:?}", expected=PROTOCOL_START)]
    BadHandshake(String),
    #[error(transparent)]
    IceError(#[from] webrtc_ice::Error),
}
impl<E: std::error::Error + IntoIoError> IntoIoError for IceError<E> {
    fn kind(&self) -> io::ErrorKind {
        match self {
            IceError::SignalingError(e) => e.kind(),
            IceError::BadHandshake(_) => io::ErrorKind::InvalidData,
            IceError::IceError(_) => io::ErrorKind::Other,
        }
    }
}
impl<E: std::error::Error + IntoIoError> From<IceError<E>> for io::Error {
    fn from(value: IceError<E>) -> Self {
        match value {
            IceError::SignalingError(e) => e.into(),
            e => io::Error::new(e.kind(), e),
        }
    }
}
pub type IceResult<T, E> = Result<T, IceError<E>>;
