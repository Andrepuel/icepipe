use crate::{
    error::TimeoutError,
    signalling::{SignalingError, Signalling},
};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use ring::{agreement, hmac, pbkdf2, rand::SystemRandom};
use std::{io, num::NonZeroU32};

pub struct Agreement<T>
where
    T: Signalling,
    T::Error: Into<SignalingError>,
{
    signalling: T,
    psk: String,
    dialer: bool,
}
impl<T> Agreement<T>
where
    T: Signalling,
    T::Error: Into<SignalingError>,
{
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
        BASE64_URL_SAFE_NO_PAD.encode(Self::derive_len(basekey, dialer, salt, 32))
    }

    pub fn new(signalling: T, psk: String, dialer: bool) -> Agreement<T> {
        Self {
            signalling,
            psk,
            dialer,
        }
    }

    pub async fn agree(mut self) -> AgreementResult<(Vec<u8>, T)> {
        let rng = SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let my_public_key = my_private_key.compute_public_key()?;

        self.signalling
            .send(BASE64_STANDARD.encode(&my_public_key))
            .await
            .map_err(Into::into)?;
        let peer_public_key = self.signalling_recv().await?;
        let peer_public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            BASE64_STANDARD.decode(&peer_public_key)?,
        );

        let key_material = agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key,
            ring::error::Unspecified,
            |key_material| Ok(key_material.to_owned()),
        )?;

        let auth_tx = self.key_material_check_tag(&key_material, self.dialer);
        let auth_rx = self.key_material_check_tag(&key_material, !self.dialer);

        self.signalling
            .send(BASE64_STANDARD.encode(auth_tx))
            .await
            .map_err(Into::into)?;
        let auth_rx_rx = self.signalling_recv().await?;
        if auth_rx.as_ref() != BASE64_STANDARD.decode(auth_rx_rx)? {
            return Err(AgreementError::TagMismatch);
        }

        Ok((key_material, self.signalling))
    }

    fn key_material_check_tag(&self, key_material: &[u8], dialer: bool) -> hmac::Tag {
        let key = hmac::Key::new(
            hmac::HMAC_SHA512,
            &Self::derive_len(&self.psk, dialer, "keymaterial_check", 32),
        );
        hmac::sign(&key, key_material)
    }

    async fn signalling_recv(&mut self) -> AgreementResult<String> {
        loop {
            let mut value = self.signalling.wait().await.map_err(Into::into)?;
            let then = self.signalling.then(&mut value).await.map_err(Into::into)?;
            match then {
                Some(key) => break Ok(key),
                None => continue,
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AgreementError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Timeout(#[from] TimeoutError),
    #[error(transparent)]
    SignalingError(SignalingError),
    #[error(transparent)]
    Base64Error(#[from] base64::DecodeError),
    #[error("Crypto error")]
    CryptoError(ring::error::Unspecified),
    #[error("Mismatch authentication tag on key agreement based on PSK")]
    TagMismatch,
}
impl From<SignalingError> for AgreementError {
    fn from(value: SignalingError) -> Self {
        match value {
            SignalingError::Timeout(e) => e.into(),
            SignalingError::Io(e) => e.into(),
            e => Self::SignalingError(e),
        }
    }
}
impl From<ring::error::Unspecified> for AgreementError {
    fn from(value: ring::error::Unspecified) -> Self {
        Self::CryptoError(value)
    }
}
pub type AgreementResult<T> = Result<T, AgreementError>;
