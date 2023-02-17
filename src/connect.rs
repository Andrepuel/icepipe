use crate::{
    agreement::{Agreement, AgreementError, PskAuthentication},
    constants,
    crypto_stream::{Chacha20Error, Chacha20Stream},
    error::TimeoutError,
    ice::{IceAgent, IceError},
    pipe_stream::StreamError,
    sctp::{Sctp, SctpError},
    signalling::SignalingError,
    ws::Websocket,
};
use std::{io, str::FromStr};

pub type Connection = Chacha20Stream<ConnectionSctp>;
type ConnectionSctp = Sctp;

pub async fn connect(
    channel: &str,
    signaling: Option<&str>,
    ice: &[String],
) -> Result<Connection, ConnectError> {
    let signaling = signaling
        .map(ToOwned::to_owned)
        .or_else(constants::signalling_server)
        .ok_or(ConnectError::NoDefaultValue(Constants::Signaling))?;
    let signaling = url::Url::parse(&signaling).map_err(ConnectError::BadSignalingUrl)?;

    let ice_urls = ice
        .to_owned()
        .into_option()
        .or_else(|| constants::ice_urls().into_option())
        .ok_or(ConnectError::NoDefaultValue(Constants::Ice))?;
    let ice_urls = ice_urls
        .into_iter()
        .map(|s| {
            ParseUrl::from_str(&s)
                .map(|u| u.0)
                .map_err(ConnectError::BadIceUrl)
        })
        .collect::<ConnectResult<_>>()?;

    let base_password = channel;
    let channel = PskAuthentication::derive_text(base_password, true, "channel");
    let url = signaling.join(&channel).unwrap();

    let (signalling, dialer) = Websocket::new(url).await.map_err(SignalingError::from)?;
    let auth = PskAuthentication::new(base_password.to_owned(), dialer);
    let agreement = Agreement::new(signalling, auth);
    let (basekey, signalling) = agreement.agree().await?;

    let mut agent = IceAgent::new(signalling, dialer, ice_urls).await?;
    let net_conn = agent.connect().await?;
    let stream = Sctp::new(net_conn, dialer, agent.connection()).await?;

    Ok(Chacha20Stream::new(&basekey, dialer, stream)?)
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    SignalingError(SignalingError),
    #[error(transparent)]
    AgreementError(AgreementError),
    #[error(transparent)]
    StreamError(StreamError),
    #[error(transparent)]
    SctpError(SctpError),
    #[error(transparent)]
    Chacha20Error(Chacha20Error),
    #[error("No default value available for signaling, must provide one")]
    NoDefaultValue(Constants),
    #[error(transparent)]
    BadSignalingUrl(url::ParseError),
    #[error(transparent)]
    BadIceUrl(webrtc_ice::Error),
}
impl From<SignalingError> for ConnectError {
    fn from(value: SignalingError) -> Self {
        match value {
            SignalingError::Io(e) => e.into(),
            SignalingError::Timeout(e) => e.into(),
            e @ SignalingError::ProtocolError(_) => Self::SignalingError(e),
        }
    }
}
impl From<AgreementError> for ConnectError {
    fn from(value: AgreementError) -> Self {
        match value {
            AgreementError::Io(e) => e.into(),
            AgreementError::Timeout(e) => e.into(),
            AgreementError::SignalingError(e) => e.into(),
            e @ AgreementError::Base64Error(_) => Self::AgreementError(e),
            e @ AgreementError::CryptoError(_) => Self::AgreementError(e),
            e @ AgreementError::BadAuth(..) => Self::AgreementError(e),
        }
    }
}
impl From<IceError> for ConnectError {
    fn from(value: IceError) -> Self {
        Self::StreamError(value.into())
    }
}
impl From<StreamError> for ConnectError {
    fn from(value: StreamError) -> Self {
        match value {
            StreamError::Io(e) => e.into(),
            StreamError::Timeout(e) => e.into(),
            StreamError::SignalingError(e) => e.into(),
            e @ StreamError::Other(_) => Self::StreamError(e),
        }
    }
}
impl From<SctpError> for ConnectError {
    fn from(value: SctpError) -> Self {
        match value {
            SctpError::Io(e) => e.into(),
            SctpError::Timeout(e) => e.into(),
            SctpError::SignalingError(e) => e.into(),
            e @ SctpError::StreamError(_) => Self::SctpError(e),
            e @ SctpError::AssociationClosedWithoutStream => Self::SctpError(e),
            e @ SctpError::WebrtcSctpError(_) => Self::SctpError(e),
        }
    }
}
impl From<Chacha20Error> for ConnectError {
    fn from(value: Chacha20Error) -> Self {
        match value {
            Chacha20Error::Io(e) => e.into(),
            Chacha20Error::Timeout(e) => e.into(),
            Chacha20Error::SignalingError(e) => e.into(),
            Chacha20Error::StreamError(e) => e.into(),
            e @ Chacha20Error::CryptoError(_) => Self::Chacha20Error(e),
        }
    }
}
pub type ConnectResult<T> = Result<T, ConnectError>;

impl From<ConnectError> for StreamError {
    fn from(value: ConnectError) -> Self {
        match value {
            ConnectError::Io(e) => e.into(),
            ConnectError::Timeout(e) => e.into(),
            ConnectError::SignalingError(e) => e.into(),
            e @ ConnectError::AgreementError(_) => Self::Other(Box::new(e)),
            ConnectError::StreamError(e) => e,
            ConnectError::SctpError(e) => e.into(),
            ConnectError::Chacha20Error(e) => e.into(),
            e @ ConnectError::NoDefaultValue(_) => StreamError::Other(Box::new(e)),
            e @ ConnectError::BadSignalingUrl(_) => StreamError::Other(Box::new(e)),
            e @ ConnectError::BadIceUrl(_) => StreamError::Other(Box::new(e)),
        }
    }
}

#[derive(Debug)]
pub enum Constants {
    Signaling,
    Ice,
}
impl std::fmt::Display for Constants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Constants::Signaling => "signaling",
                Constants::Ice => "ice",
            }
        )
    }
}

trait Optional: Sized {
    fn into_option(self) -> Option<Self>;
}
impl<T> Optional for Vec<T> {
    fn into_option(self) -> Option<Self> {
        (!self.is_empty()).then_some(self)
    }
}

struct ParseUrl(webrtc_ice::url::Url);
impl FromStr for ParseUrl {
    type Err = webrtc_ice::Error;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let mut fields = url.split('&');
        let url = fields.next().unwrap_or_default();
        let username = fields.next();
        let password = fields.next();
        let mut url = webrtc_ice::url::Url::parse_url(url)?;
        url.username = username.unwrap_or_default().to_owned();
        url.password = password.unwrap_or_default().to_owned();

        Ok(ParseUrl(url))
    }
}
