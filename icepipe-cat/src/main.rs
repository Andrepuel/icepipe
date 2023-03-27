use clap::Parser;
use icepipe::{
    agreement::Ed25519PairAndPeer,
    async_pipe_stream::{AsyncPipeStream, DynAsyncRead, DynAsyncWrite},
    curve25519_conversion,
    pipe_stream::{Control, PipeStream, StreamError, StreamResult, WaitThen},
    ring::signature::{self, KeyPair},
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};

fn main() -> StreamResult<()> {
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
    /// If private key is provided, channel is assumed to be the peer public key.
    channel: String,

    /// Private key for DH mode. Channel will be assumed to be peers public key.
    #[clap(long = "private-key")]
    private_key: Option<String>,

    /// Generates a new key pair and closes the prorgam
    #[clap(long = "gen-key")]
    gen_key: bool,

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

async fn main2() -> StreamResult<()> {
    let args = Args::parse();

    if args.gen_key {
        return gen_key()
            .map_err(icepipe::agreement::AgreementError::from)
            .map_err(|e| StreamError::Other(Box::new(e)));
    }

    let options = icepipe::ConnectOptions {
        channel: args.channel,
        signaling: args
            .signaling
            .map(|url| url.parse().map_err(|e| StreamError::Other(Box::new(e))))
            .transpose()?,
        ice: args.ice,
    };

    let mut peer_stream = match args.private_key {
        Some(private_key) => {
            let (key_pair, peer, x_key_pair, x_peer) = get_keys(private_key, options.channel)
                .map_err(icepipe::agreement::AgreementError::from)
                .map_err(|e| StreamError::Other(Box::new(e)))?;

            let channel = x_key_pair
                .diffie_hellman(&x_peer)
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();

            let options = icepipe::ConnectOptions { channel, ..options };

            let auth = Ed25519PairAndPeer(key_pair, peer);

            options.connect(auth).await?
        }
        None => options.connect_psk().await?,
    };

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

    log::info!("ready to close");

    Ok(())
}

fn gen_key() -> Result<(), icepipe::ring::error::Unspecified> {
    let seed: [u8; 32] =
        icepipe::ring::rand::generate(&icepipe::ring::rand::SystemRandom::new())?.expose();
    let key = signature::Ed25519KeyPair::from_seed_unchecked(&seed)?;
    let private_key = seed.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let public_key = key
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!("--private-key {private_key}");
    println!("Public key: {public_key}");

    Ok(())
}

fn get_keys(
    private_key: String,
    peer: String,
) -> Result<
    (
        signature::Ed25519KeyPair,
        Vec<u8>,
        icepipe::x25519_dalek::StaticSecret,
        icepipe::x25519_dalek::PublicKey,
    ),
    icepipe::ring::error::Unspecified,
> {
    let seed = (0..private_key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&private_key[i..][..2], 16).unwrap_or_default())
        .collect::<Vec<_>>();

    let peer = (0..peer.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&peer[i..][..2], 16).unwrap_or_default())
        .collect::<Vec<_>>();

    let private_key = icepipe::ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)?;

    let x25519 = curve25519_conversion::ed25519_seed_to_x25519(&seed);
    let x25519_peer = curve25519_conversion::ed25519_public_key_to_x25519(&peer)
        .ok_or(icepipe::ring::error::Unspecified)?;

    Ok((private_key, peer, x25519, x25519_peer))
}
