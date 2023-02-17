use clap::Parser;
use icepipe::{
    async_pipe_stream::{AsyncPipeStream, DynAsyncRead, DynAsyncWrite},
    pipe_stream::{Control, PipeStream, StreamResult, WaitThen},
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

async fn main2() -> StreamResult<()> {
    let args = Args::parse();

    let mut peer_stream =
        icepipe::connect(&args.channel, args.signaling.as_deref(), &args.ice).await?;

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
