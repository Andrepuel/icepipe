use crate::{
    error::TimeoutError,
    signalling::{SignalingError, Signalling},
};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use ring::{
    agreement, hmac, pbkdf2,
    rand::SystemRandom,
    signature::{self, VerificationAlgorithm},
};
use std::{io, num::NonZeroU32};

pub struct Agreement<T, A>
where
    T: Signalling,
    T::Error: Into<SignalingError>,
    A: Authentication,
{
    signalling: T,
    auth: A,
}
impl<T, A> Agreement<T, A>
where
    T: Signalling,
    T::Error: Into<SignalingError>,
    A: Authentication,
{
    pub fn new(signalling: T, auth: A) -> Agreement<T, A> {
        Self { signalling, auth }
    }

    pub async fn agree(mut self) -> AgreementResult<(Vec<u8>, T)> {
        let rng = SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let my_public_key = my_private_key.compute_public_key()?;

        self.signalling
            .send(BASE64_STANDARD.encode(&my_public_key))
            .await
            .map_err(Into::into)?;

        self.signalling
            .send(BASE64_STANDARD.encode(self.auth.sign(my_public_key.as_ref())))
            .await
            .map_err(Into::into)?;

        let peer_public_key = self.signalling_recv().await?;
        let peer_public_key = BASE64_STANDARD.decode(&peer_public_key)?;
        let peer_public_key_signature = self.signalling_recv().await?;
        let peer_public_key_signature = BASE64_STANDARD.decode(peer_public_key_signature)?;
        self.auth
            .check_peer(&peer_public_key, &peer_public_key_signature)
            .map_err(|e| AgreementError::BadAuth(Box::new(e)))?;
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);

        let key_material = agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key,
            ring::error::Unspecified,
            |key_material| Ok(key_material.to_owned()),
        )?;

        Ok((key_material, self.signalling))
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
    #[error("Mismatch authentication tag on key agreement based on PSK, {0}")]
    BadAuth(Box<AgreementError>),
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

pub trait Authentication {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
    fn check_peer(&self, data: &[u8], signature: &[u8]) -> AgreementResult<()>;
}

pub struct PskAuthentication {
    psk: String,
    dialer: bool,
}
impl PskAuthentication {
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

    pub fn new(psk: String, dialer: bool) -> PskAuthentication {
        PskAuthentication { psk, dialer }
    }

    fn key(&self, purpose: HmacKeyPurpose) -> hmac::Key {
        let dialer = match purpose {
            HmacKeyPurpose::Signing => self.dialer,
            HmacKeyPurpose::Verifying => !self.dialer,
        };

        hmac::Key::new(
            hmac::HMAC_SHA512,
            &Self::derive_len(&self.psk, dialer, "keymaterial_check", 32),
        )
    }
}
impl Authentication for PskAuthentication {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        hmac::sign(&self.key(HmacKeyPurpose::Signing), data)
            .as_ref()
            .to_owned()
    }

    fn check_peer(&self, data: &[u8], signature: &[u8]) -> AgreementResult<()> {
        Ok(hmac::verify(
            &self.key(HmacKeyPurpose::Verifying),
            data,
            signature,
        )?)
    }
}

enum HmacKeyPurpose {
    Signing,
    Verifying,
}

struct Ed25519PairAndPeer(signature::Ed25519KeyPair, Vec<u8>);
impl Authentication for Ed25519PairAndPeer {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.0.sign(data).as_ref().to_owned()
    }

    fn check_peer(&self, data: &[u8], signature: &[u8]) -> AgreementResult<()> {
        Ok(signature::ED25519.verify(self.1.as_slice().into(), data.into(), signature.into())?)
    }
}
