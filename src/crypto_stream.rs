use std::{any::Any, num::NonZeroU32};

use futures_util::future::ready;
use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305,
    },
    error::Unspecified,
    pbkdf2::{self, PBKDF2_HMAC_SHA256},
};

use crate::{
    pipe_stream::{Control, PipeStream, WaitThen},
    DynResult, PinFutureLocal,
};

pub struct Sequential(u64);
impl NonceSequence for Sequential {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let seq = self.0.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&seq);

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

pub struct Chacha20Stream {
    sealing_key: SealingKey<Sequential>,
    opening_key: OpeningKey<Sequential>,
    underlying: Box<dyn PipeStream>,
}
impl Chacha20Stream {
    pub fn derive(basekey: &str, dialer: bool, salt: &str, out: &mut [u8]) {
        let salt = format!(
            "{}:{}",
            match dialer {
                true => "dialer",
                false => "listener",
            },
            salt
        );
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            NonZeroU32::new(4096).unwrap(),
            salt.as_bytes(),
            basekey.as_bytes(),
            out,
        );
    }

    pub fn derive_text(basekey: &str, dialer: bool, salt: &str) -> String {
        let mut data = vec![0; 32];
        Self::derive(basekey, dialer, salt, &mut data);

        base64::encode_config(&data, base64::URL_SAFE_NO_PAD)
    }

    fn get_key(basekey: &str, dialer: bool) -> DynResult<UnboundKey> {
        let mut key_bytes = vec![0; 32];
        Self::derive(basekey, dialer, "key", &mut key_bytes);

        Ok(UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).ring_err()?)
    }

    fn get_seq(basekey: &str, dialer: bool) -> Sequential {
        let mut u64_be = [0; 8];
        Self::derive(basekey, dialer, "seq", &mut u64_be);

        Sequential(u64::from_be_bytes(u64_be))
    }

    pub fn new<T: PipeStream + 'static>(
        basekey: &str,
        dialer: bool,
        underlying: T,
    ) -> DynResult<Chacha20Stream> {
        Self::new_dyn(basekey, dialer, Box::new(underlying))
    }

    pub fn new_dyn(
        basekey: &str,
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
