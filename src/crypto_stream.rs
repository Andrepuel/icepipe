use crate::{
    pipe_stream::{Control, PipeStream, WaitThen},
    DynResult, PinFutureLocal,
};
use futures::future::ready;
use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305,
    },
    error::Unspecified,
    hkdf::{self, KeyType},
};
use std::any::Any;

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

pub trait RingError<T>: Into<Result<T, Unspecified>> {
    fn ring_err(self) -> DynResult<T> {
        self.into().map_err(|_| anyhow::anyhow!("Crypto error"))
    }
}
impl<T> RingError<T> for Result<T, Unspecified> {}

impl hkdf::KeyType for Sequential {
    fn len(&self) -> usize {
        16
    }
}

pub struct Chacha20Stream {
    sealing_key: SealingKey<Sequential>,
    opening_key: OpeningKey<Sequential>,
    underlying: Box<dyn PipeStream>,
}
impl Chacha20Stream {
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

    fn get_key(basekey: &[u8], dialer: bool) -> DynResult<UnboundKey> {
        let mut key_bytes = [0; 32];
        Self::derive(basekey, dialer, "key", &CHACHA20_POLY1305, &mut key_bytes);

        UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).ring_err()
    }

    fn get_seq(basekey: &[u8], dialer: bool) -> Sequential {
        let mut u128_be = [0; 16];
        Self::derive(basekey, dialer, "seq", Sequential(0), &mut u128_be);

        Sequential(u128::from_be_bytes(u128_be))
    }

    pub fn new<T: PipeStream + 'static>(
        basekey: &[u8],
        dialer: bool,
        underlying: T,
    ) -> DynResult<Chacha20Stream> {
        Self::new_dyn(basekey, dialer, Box::new(underlying))
    }

    pub fn new_dyn(
        basekey: &[u8],
        dialer: bool,
        underlying: Box<dyn PipeStream>,
    ) -> DynResult<Chacha20Stream> {
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
impl PipeStream for Chacha20Stream {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> PinFutureLocal<'a, ()> {
        let mut data = data.to_owned();

        if let Err(e) = self
            .sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut data)
            .ring_err()
        {
            return Box::pin(ready(Err(e)));
        }

        Box::pin(async move { self.underlying.send(&data).await })
    }
}
impl WaitThen for Chacha20Stream {
    type Value = Box<dyn Any>;
    type Output = Option<Vec<u8>>;

    fn wait(&mut self) -> PinFutureLocal<'_, Self::Value> {
        self.underlying.wait_dyn()
    }

    fn then<'a>(&'a mut self, value: &'a mut Self::Value) -> PinFutureLocal<'a, Self::Output> {
        Box::pin(async move {
            let mut data: Option<Vec<u8>> = self.underlying.then_dyn(value).await?;
            let r = match data.as_mut() {
                Some(data) => Some(
                    self.opening_key
                        .open_in_place(Aad::empty(), data)
                        .ring_err()?
                        .to_owned(),
                ),
                None => None,
            };

            Ok(r)
        })
    }
}
impl Control for Chacha20Stream {
    fn close(&mut self) -> PinFutureLocal<'_, ()> {
        self.underlying.close()
    }

    fn rx_closed(&self) -> bool {
        self.underlying.rx_closed()
    }
}
