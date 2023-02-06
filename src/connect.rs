use crate::{
    agreement::{Agreement, AgreementError},
    constants,
    crypto_stream::{Chacha20Error, Chacha20Stream},
    ice::{IceAgent, IceError},
    pipe_stream::WaitThen,
    sctp::{Sctp, SctpError},
    ws::Websocket,
    IntoIoError,
};
use std::{io, str::FromStr};

pub type Connection = Chacha20Stream<ConnectionSctp>;
type ConnectionSctp = Sctp<ConnectionControl>;
type ConnectionControl = IceAgent<ConnectionSignaling>;
type ConnectionSignaling = Websocket;

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
    let channel = Agreement::<Websocket>::derive_text(base_password, true, "channel");
    let url = signaling.join(&channel).unwrap();

    let (signalling, dialer) = Websocket::new(url)
        .await
        .map_err(|e| ConnectError::Io(e.into()))?;
    let agreement = Agreement::new(signalling, base_password.to_owned(), dialer);
    let (basekey, signalling) = agreement.agree().await?;

    let mut agent = IceAgent::new(signalling, dialer, ice_urls).await?;
    let net_conn = agent.connect().await?;
    let stream = Sctp::new(net_conn, dialer, agent).await?;

    Ok(Chacha20Stream::new(&basekey, dialer, stream)?)
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error("No default value available for signaling, must provide one")]
    NoDefaultValue(Constants),
    #[error(transparent)]
    BadSignalingUrl(url::ParseError),
    #[error(transparent)]
    BadIceUrl(webrtc_ice::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    AgreementError(AgreementError<<ConnectionSignaling as WaitThen>::Error>),
    #[error(transparent)]
    Chacha20Error(Chacha20Error<<ConnectionSctp as WaitThen>::Error>),
    #[error(transparent)]
    SctpError(SctpError<<ConnectionControl as WaitThen>::Error>),
    #[error(transparent)]
    IceError(IceError<<ConnectionSignaling as WaitThen>::Error>),
    #[error(transparent)]
    SignalingError(#[from] <ConnectionSignaling as WaitThen>::Error),
}
impl IntoIoError for ConnectError {
    fn kind(&self) -> io::ErrorKind {
        match self {
            ConnectError::NoDefaultValue(_) => io::ErrorKind::InvalidInput,
            ConnectError::BadSignalingUrl(_) => io::ErrorKind::InvalidInput,
            ConnectError::BadIceUrl(_) => io::ErrorKind::InvalidInput,
            ConnectError::Io(e) => e.kind(),
            ConnectError::AgreementError(e) => e.kind(),
            ConnectError::Chacha20Error(e) => e.kind(),
            ConnectError::SctpError(e) => e.kind(),
            ConnectError::IceError(e) => e.kind(),
            ConnectError::SignalingError(e) => e.kind(),
        }
    }
}
impl From<ConnectError> for io::Error {
    fn from(value: ConnectError) -> Self {
        match value {
            ConnectError::Io(e) => e,
            ConnectError::AgreementError(e) => e.into(),
            ConnectError::Chacha20Error(e) => e.into(),
            ConnectError::SctpError(e) => e.into(),
            ConnectError::IceError(e) => e.into(),
            ConnectError::SignalingError(e) => e.into(),
            e => io::Error::new(e.kind(), e),
        }
    }
}

pub type ConnectResult<T> = Result<T, ConnectError>;
impl From<AgreementError<<ConnectionSignaling as WaitThen>::Error>> for ConnectError {
    fn from(value: AgreementError<<ConnectionSignaling as WaitThen>::Error>) -> Self {
        match value {
            AgreementError::SignalingError(e) => e.into(),
            e => ConnectError::AgreementError(e),
        }
    }
}
impl From<Chacha20Error<<ConnectionSctp as WaitThen>::Error>> for ConnectError {
    fn from(value: <Connection as WaitThen>::Error) -> Self {
        match value {
            Chacha20Error::StreamError(e) => e.into(),
            e => ConnectError::Chacha20Error(e),
        }
    }
}
impl From<SctpError<<ConnectionControl as WaitThen>::Error>> for ConnectError {
    fn from(value: SctpError<<ConnectionControl as WaitThen>::Error>) -> Self {
        match value {
            SctpError::ControlError(e) => e.into(),
            e => ConnectError::SctpError(e),
        }
    }
}
impl From<IceError<<ConnectionSignaling as WaitThen>::Error>> for ConnectError {
    fn from(value: IceError<<ConnectionSignaling as WaitThen>::Error>) -> Self {
        match value {
            IceError::SignalingError(e) => e.into(),
            e => ConnectError::IceError(e),
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
