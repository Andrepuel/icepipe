use clap::Parser;
use icepipe::{
    agreement::Agreement,
    async_pipe_stream::{AsyncPipeStream, DynAsyncRead, DynAsyncWrite},
    constants,
    crypto_stream::Chacha20Stream,
    ice::IceAgent,
    pipe_stream::{Control, PipeStream, WaitThen},
    sctp::Sctp,
    ws::Websocket,
    DynResult,
};
use std::{process, str::FromStr};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};

fn main() -> DynResult<()> {
    env_logger::init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(main2())
}

/// Establishes P2P connection between two peers
#[derive(Parser)]
struct Args {
    /// Channel to connect to, both side must pass the same value to establish a connection
    channel: String,

    /// Specify a different signalling server URL
    #[clap(long = "signaling")]
    signaling: Option<String>,

    /// Url of STUN or TURN server. Example: turn:my.stun.com:19302&username&password
    #[clap(long = "ice")]
    ice: Vec<String>,

    /// Specify input file path to be forward to the peer. Default: read from standard input
    #[clap(short = 'i', long = "input")]
    input: Option<String>,

    /// Specify input file as a listening port that will accept one connection.
    #[clap(short = 'L', long = "tcp-input")]
    tcp_input: Option<String>,

    /// Specify output file path to b created with contents received from peer. Default: write to standard output
    #[clap(short = 'o', long = "output")]
    output: Option<String>,

    /// Forwards both input and output to a new TCP connection established with the specified address.
    #[clap(short = 'W', long = "tcp-forward")]
    tcp_forward: Option<String>,
}

async fn main2() -> DynResult<()> {
    let args = Args::parse();

    let signaling = args
        .signaling
        .or_else(constants::signalling_server)
        .ok_or_else(|| {
            anyhow::anyhow!("No default value available for signaling, must provide one")
        })?;
    let signaling = url::Url::parse(&signaling)?;

    let ice_urls = args
        .ice
        .into_option()
        .or_else(|| constants::ice_urls().into_option())
        .ok_or_else(|| anyhow::anyhow!("No default value available for ice, must provide one"))?;
    let ice_urls = ice_urls
        .into_iter()
        .map(|s| ParseUrl::from_str(&s).map(|u| u.0))
        .collect::<DynResult<_>>()?;

    let base_password = args.channel;
    let channel = Agreement::<Websocket>::derive_text(&base_password, true, "channel");
    let url = signaling.join(&channel).unwrap();

    let (signalling, dialer) = Websocket::new(url).await?;
    let agreement = Agreement::new(signalling, base_password, dialer);
    let (basekey, signalling) = agreement.agree().await?;

    let mut agent = IceAgent::new(signalling, dialer, ice_urls).await?;
    let net_conn = agent.connect().await?;
    let stream = Sctp::new(net_conn, dialer, agent).await?;
    let mut peer_stream = Chacha20Stream::new(&basekey, dialer, stream)?;

    let input: DynAsyncRead;
    let output: DynAsyncWrite;
    if let Some(tcp_input) = args.tcp_input {
        assert!(
            args.input.is_none(),
            "--input and --tcp-input are mutually exclusive"
        );
        assert!(
            args.output.is_none(),
            "--output and --tcp-input are mutually exclusive"
        );
        assert!(
            args.tcp_forward.is_none(),
            "--tcp-input and --tcp-forward are mutually exclusive"
        );

        let tcp_listen = TcpListener::bind(tcp_input).await?;
        let (tcp_stream, _) = tcp_listen.accept().await?;
        let (read, write) = tcp_stream.into_split();
        input = Box::pin(read);
        output = Box::pin(write);
    } else if let Some(tcp_forward) = args.tcp_forward {
        assert!(
            args.input.is_none(),
            "--input and --tcp-forward are mutually exclusive"
        );
        assert!(
            args.output.is_none(),
            "--output and --tcp-forward are mutually exclusive"
        );

        log::info!("Connecting to {tcp_forward}");
        let tcp_stream = TcpStream::connect(tcp_forward).await?;
        let (read, write) = tcp_stream.into_split();
        input = Box::pin(read);
        output = Box::pin(write);
    } else {
        input = match args.input {
            Some(path) => Box::pin(tokio::fs::File::open(path).await?),
            None => Box::pin(tokio::io::stdin()),
        };
        output = match args.output {
            Some(path) => Box::pin(tokio::fs::File::create(path).await?),
            None => Box::pin(tokio::io::stdout()),
        };
    }

    let mut local_stream = AsyncPipeStream::new_dyn(input, output);

    while !peer_stream.rx_closed() && !local_stream.rx_closed() {
        select! {
            value = peer_stream.wait() => {
                let recv = peer_stream.then(&mut value?).await?;
                if let Some(data) = recv {
                    local_stream.send(&data).await?;
                }
            }
            value = local_stream.wait() => {
                let recv = local_stream.then(&mut value?).await?;
                if let Some(data) = recv {
                    peer_stream.send(&data).await?;
                }
            },
        }
    }
    peer_stream.close().await?;
    local_stream.close().await?;

    process::exit(0);
}

trait Optional: Sized {
    fn into_option(self) -> Option<Self>;
}
impl<T> Optional for Vec<T> {
    fn into_option(self) -> Option<Self> {
        (!self.is_empty()).then(move || self)
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
