use crate::{
    agreement::Agreement, constants, crypto_stream::Chacha20Stream, ice::IceAgent, sctp::Sctp,
    ws::Websocket, DynResult,
};
use std::str::FromStr;

pub async fn connect(
    channel: &str,
    signaling: Option<&str>,
    ice: &[String],
) -> DynResult<Chacha20Stream> {
    let signaling = signaling
        .map(ToOwned::to_owned)
        .or_else(constants::signalling_server)
        .ok_or_else(|| {
            anyhow::anyhow!("No default value available for signaling, must provide one")
        })?;
    let signaling = url::Url::parse(&signaling)?;

    let ice_urls = ice
        .to_owned()
        .into_option()
        .or_else(|| constants::ice_urls().into_option())
        .ok_or_else(|| anyhow::anyhow!("No default value available for ice, must provide one"))?;
    let ice_urls = ice_urls
        .into_iter()
        .map(|s| ParseUrl::from_str(&s).map(|u| u.0))
        .collect::<DynResult<_>>()?;

    let base_password = channel;
    let channel = Agreement::<Websocket>::derive_text(base_password, true, "channel");
    let url = signaling.join(&channel).unwrap();

    let (signalling, dialer) = Websocket::new(url).await?;
    let agreement = Agreement::new(signalling, base_password.to_owned(), dialer);
    let (basekey, signalling) = agreement.agree().await?;

    let mut agent = IceAgent::new(signalling, dialer, ice_urls).await?;
    let net_conn = agent.connect().await?;
    let stream = Sctp::new(net_conn, dialer, agent).await?;

    Chacha20Stream::new(&basekey, dialer, stream)
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
    type Err = anyhow::Error;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let mut fields = url.split('&');
        let url = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("Empty STUN url"))?;
        let username = fields.next();
        let password = fields.next();
        let mut url = webrtc_ice::url::Url::parse_url(url)?;
        url.username = username.unwrap_or_default().to_owned();
        url.password = password.unwrap_or_default().to_owned();

        DynResult::Ok(ParseUrl(url))
    }
}
