use std::io;

use crate::{
    pipe_stream::{Control, PipeStream, WaitThen},
    IntoIoError,
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

pub struct Chacha20Stream<S: PipeStream> {
    sealing_key: SealingKey<Sequential>,
    opening_key: OpeningKey<Sequential>,
    underlying: S,
}
impl<S: PipeStream> Chacha20Stream<S> {
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

    fn get_key(basekey: &[u8], dialer: bool) -> Chacha20Result<UnboundKey, S::Error> {
        let mut key_bytes = [0; 32];
        Self::derive(basekey, dialer, "key", &CHACHA20_POLY1305, &mut key_bytes);

        UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).map_err(Chacha20Error::CryptoError)
    }

    fn get_seq(basekey: &[u8], dialer: bool) -> Sequential {
        let mut u128_be = [0; 16];
        Self::derive(basekey, dialer, "seq", Sequential(0), &mut u128_be);

        Sequential(u128::from_be_bytes(u128_be))
    }

    pub fn new(basekey: &[u8], dialer: bool, underlying: S) -> Chacha20Result<Self, S::Error> {
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
impl<S: PipeStream> PipeStream for Chacha20Stream<S> {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> LocalBoxFuture<'a, Chacha20Result<(), S::Error>> {
        let mut data = data.to_owned();

        if let Err(e) = self
            .sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut data)
            .map_err(Chacha20Error::CryptoError)
        {
            return Box::pin(ready(Err(e)));
        }

        async move { Ok(self.underlying.send(&data).await?) }.boxed_local()
    }
}
impl<S: PipeStream> WaitThen for Chacha20Stream<S> {
    type Value = S::Value;
    type Output = Option<Vec<u8>>;
    type Error = Chacha20Error<S::Error>;

    fn wait(&mut self) -> LocalBoxFuture<'_, Chacha20Result<Self::Value, S::Error>> {
        async move { Ok(self.underlying.wait().await?) }.boxed_local()
    }

    fn then<'a>(
        &'a mut self,
        value: &'a mut Self::Value,
    ) -> LocalBoxFuture<'a, Chacha20Result<Self::Output, S::Error>> {
        Box::pin(async move {
            let mut data: Option<Vec<u8>> = self.underlying.then(value).await?;
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
impl<S: PipeStream> Control for Chacha20Stream<S> {
    fn close(&mut self) -> LocalBoxFuture<'_, Chacha20Result<(), S::Error>> {
        async move { Ok(self.underlying.close().await?) }.boxed_local()
    }

    fn rx_closed(&self) -> bool {
        self.underlying.rx_closed()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Chacha20Error<E: std::error::Error> {
    #[error(transparent)]
    StreamError(#[from] E),
    #[error("Crypto error")]
    CryptoError(Unspecified),
}
impl<E: std::error::Error + IntoIoError> IntoIoError for Chacha20Error<E> {
    fn kind(&self) -> io::ErrorKind {
        match self {
            Chacha20Error::StreamError(e) => e.kind(),
            Chacha20Error::CryptoError(_) => io::ErrorKind::Other,
        }
    }
}
impl<E: std::error::Error + IntoIoError> From<Chacha20Error<E>> for io::Error {
    fn from(value: Chacha20Error<E>) -> Self {
        match value {
            Chacha20Error::StreamError(e) => e.into(),
            e => io::Error::new(e.kind(), e),
        }
    }
}
pub type Chacha20Result<T, E> = Result<T, Chacha20Error<E>>;
