use crate::{
    error::TimeoutError,
    pipe_stream::{Control, PipeStream, StreamError, WaitThen},
    signalling::SignalingError,
};
use futures::{
    future::{ready, LocalBoxFuture},
    FutureExt,
};
use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305,
    },
    error::Unspecified,
    hkdf::{self, KeyType},
};
use std::io;

pub struct Sequential(u128);
impl NonceSequence for Sequential {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let seq = self.0.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[..].copy_from_slice(&seq[4..16]);

        self.0 += 1;

        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

impl hkdf::KeyType for Sequential {
    fn len(&self) -> usize {
        16
    }
}

pub struct Chacha20Stream<S>
where
    S: PipeStream,
    S::Error: Into<StreamError>,
{
    sealing_key: SealingKey<Sequential>,
    opening_key: OpeningKey<Sequential>,
    underlying: S,
}
impl<S> Chacha20Stream<S>
where
    S: PipeStream,
    S::Error: Into<StreamError>,
{
    pub fn derive<L: KeyType>(
        basekey: &[u8],
        dialer: bool,
        salt: &str,
        key_type: L,
        out: &mut [u8],
    ) {
        let info = match dialer {
            true => "dialer",
            false => "listener",
        };
        let algorithm = hkdf::HKDF_SHA512;
        let info = [info.as_bytes()];
        let salt = hkdf::Salt::new(algorithm, salt.as_bytes());
        let prk = salt.extract(basekey);
        let okm = prk.expand(&info, key_type).unwrap();
        okm.fill(out).unwrap();
    }

    fn get_key(basekey: &[u8], dialer: bool) -> Chacha20Result<UnboundKey> {
        let mut key_bytes = [0; 32];
        Self::derive(basekey, dialer, "key", &CHACHA20_POLY1305, &mut key_bytes);

        UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).map_err(Chacha20Error::CryptoError)
    }

    fn get_seq(basekey: &[u8], dialer: bool) -> Sequential {
        let mut u128_be = [0; 16];
        Self::derive(basekey, dialer, "seq", Sequential(0), &mut u128_be);

        Sequential(u128::from_be_bytes(u128_be))
    }

    pub fn new(basekey: &[u8], dialer: bool, underlying: S) -> Chacha20Result<Self> {
        let sealing = Self::get_key(basekey, dialer)?;
        let sealing_seq = Self::get_seq(basekey, dialer);
        let opening = Self::get_key(basekey, !dialer)?;
        let opening_seq = Self::get_seq(basekey, !dialer);
        let sealing_key = BoundKey::new(sealing, sealing_seq);
        let opening_key = BoundKey::new(opening, opening_seq);

        Ok(Chacha20Stream {
            sealing_key,
            opening_key,
            underlying,
        })
    }
}
impl<S> PipeStream for Chacha20Stream<S>
where
    S: PipeStream,
    S::Error: Into<StreamError>,
{
    fn send<'a>(&'a mut self, data: &'a [u8]) -> LocalBoxFuture<'a, Chacha20Result<()>> {
        let mut data = data.to_owned();

        if let Err(e) = self
            .sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut data)
            .map_err(Chacha20Error::CryptoError)
        {
            return Box::pin(ready(Err(e)));
        }

        async move { Ok(self.underlying.send(&data).await.map_err(Into::into)?) }.boxed_local()
    }
}
impl<S> WaitThen for Chacha20Stream<S>
where
    S: PipeStream,
    S::Error: Into<StreamError>,
{
    type Value = S::Value;
    type Output = Option<Vec<u8>>;
    type Error = Chacha20Error;

    fn wait(&mut self) -> LocalBoxFuture<'_, Chacha20Result<Self::Value>> {
        async move { Ok(self.underlying.wait().await.map_err(Into::into)?) }.boxed_local()
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> LocalBoxFuture<'a, Chacha20Result<Self::Output>> {
        Box::pin(async move {
            let mut data: Option<Vec<u8>> =
                self.underlying.then(value).await.map_err(Into::into)?;
            let r = match data.as_mut() {
                Some(data) => Some(
                    self.opening_key
                        .open_in_place(Aad::empty(), data)
                        .map_err(Chacha20Error::CryptoError)?
                        .to_owned(),
                ),
                None => None,
            };

            Ok(r)
        })
    }
}
impl<S> Control for Chacha20Stream<S>
where
    S: PipeStream,
    S::Error: Into<StreamError>,
{
    fn close(&mut self) -> LocalBoxFuture<'_, Chacha20Result<()>> {
        async move { Ok(self.underlying.close().await.map_err(Into::into)?) }.boxed_local()
    }

    fn rx_closed(&self) -> bool {
        self.underlying.rx_closed()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Chacha20Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    SignalingError(SignalingError),
    #[error(transparent)]
    StreamError(StreamError),
    #[error("Crypto error")]
    CryptoError(Unspecified),
}
impl From<SignalingError> for Chacha20Error {
    fn from(value: SignalingError) -> Self {
        match value {
            SignalingError::Io(e) => e.into(),
            SignalingError::Timeout(e) => e.into(),
            e @ SignalingError::ProtocolError(_) => Self::SignalingError(e),
        }
    }
}
impl From<StreamError> for Chacha20Error {
    fn from(value: StreamError) -> Self {
        match value {
            StreamError::Io(e) => e.into(),
            StreamError::Timeout(e) => e.into(),
            StreamError::SignalingError(e) => e.into(),
            e @ StreamError::Other(_) => Self::StreamError(e),
        }
    }
}
pub type Chacha20Result<T> = Result<T, Chacha20Error>;

impl From<Chacha20Error> for StreamError {
    fn from(value: Chacha20Error) -> Self {
        match value {
            Chacha20Error::Io(e) => e.into(),
            Chacha20Error::Timeout(e) => e.into(),
            Chacha20Error::SignalingError(e) => e.into(),
            Chacha20Error::StreamError(e) => e,
            e @ Chacha20Error::CryptoError(_) => Self::Other(Box::new(e)),
        }
    }
}
