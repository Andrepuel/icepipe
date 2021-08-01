use std::num::NonZeroU32;

use ring::{agreement, hmac, pbkdf2, rand::SystemRandom};

use crate::{
    crypto_stream::RingError, pipe_stream::WaitThenDynExt, signalling::Signalling, DynResult,
};

pub struct Agreement<T: Signalling> {
    signalling: T,
    psk: String,
    dialer: bool,
}
impl<T: Signalling> Agreement<T> {
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
            pbkdf2::PBKDF2_HMAC_SHA512,
            NonZeroU32::new(4096).unwrap(),
            salt.as_bytes(),
            basekey.as_bytes(),
            out,
        );
    }

    pub fn derive_len(basekey: &str, dialer: bool, salt: &str, len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        Self::derive(basekey, dialer, salt, &mut data);
        data
    }

    pub fn derive_text(basekey: &str, dialer: bool, salt: &str) -> String {
        base64::encode_config(
            &Self::derive_len(basekey, dialer, salt, 32),
            base64::URL_SAFE_NO_PAD,
        )
    }

    pub fn new(signalling: T, psk: String, dialer: bool) -> Agreement<T> {
        Self {
            signalling,
            psk,
            dialer,
        }
    }

    pub async fn agree(mut self) -> DynResult<(Vec<u8>, T)> {
        let rng = SystemRandom::new();
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).ring_err()?;
        let my_public_key = my_private_key.compute_public_key().ring_err()?;

        self.signalling.send(base64::encode(&my_public_key)).await?;
        let peer_public_key = self.signalling_recv().await?;
        let peer_public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            base64::decode(&peer_public_key)?,
        );

        let key_material = agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key,
            ring::error::Unspecified,
            |key_material| Ok(key_material.to_owned()),
        )
        .ring_err()?;

        let auth_tx = self.key_material_check_tag(&key_material, self.dialer);
        let auth_rx = self.key_material_check_tag(&key_material, !self.dialer);

        self.signalling.send(base64::encode(&auth_tx)).await?;
        let auth_rx_rx = self.signalling_recv().await?;
        if auth_rx.as_ref() != base64::decode(&auth_rx_rx)? {
            return Err(anyhow::anyhow!(
                "Mismatch authentication tag on key agreement based on PSK."
            ));
        }

        Ok((key_material, self.signalling))
    }

    fn key_material_check_tag(&self, key_material: &[u8], dialer: bool) -> hmac::Tag {
        let key = hmac::Key::new(
            hmac::HMAC_SHA512,
            &Self::derive_len(&self.psk, dialer, "keymaterial_check", 32),
        );
        hmac::sign(&key, &key_material)
    }

    async fn signalling_recv(&mut self) -> DynResult<String> {
        loop {
            match self.signalling.recv().await? {
                Some(key) => break Ok(key),
                None => continue,
            }
        }
    }
}
