use curve25519_dalek::edwards::CompressedEdwardsY;

///! Remarks:
///
/// When using key-based connection, the static keys are used to sign the
/// public part of the ephemeral keys. We are going to use a ephemeral diffie hellmann
/// in order to share a secret and encrypt the channel with this secret.
///
/// X255519 is used as a means of peers agreeing on which signaling channel
/// they are going to communicate on to exchange the connection, the channel
/// name is not relevant for the security of the communication.

pub fn ed25519_public_key_to_x25519(public_key: &[u8]) -> Option<x25519_dalek::PublicKey> {
    let public_point = CompressedEdwardsY::from_slice(public_key)
        .decompress()?
        .to_montgomery();

    let bytes: [u8; 32] = public_point.to_bytes();

    Some(x25519_dalek::PublicKey::from(bytes))
}

pub fn ed25519_seed_to_x25519(seed: &[u8]) -> x25519_dalek::StaticSecret {
    let sha512 = ring::digest::digest(&ring::digest::SHA512, seed);
    let mut key: [u8; 32] = sha512.as_ref()[0..32].try_into().unwrap();
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;

    x25519_dalek::StaticSecret::from(key)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ring::signature::{self, KeyPair};

    #[test]
    fn generate_keys_and_convert() {
        let seed: [u8; 32] = ring::rand::generate(&ring::rand::SystemRandom::new())
            .unwrap()
            .expose();

        let ed_keypair = signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let ed_public_key = ed_keypair.public_key();
        let ed_public_key_as_x = ed25519_public_key_to_x25519(ed_public_key.as_ref()).unwrap();

        let x_keypair = ed25519_seed_to_x25519(&seed);
        let x_public_key = x25519_dalek::PublicKey::from(&x_keypair);

        assert_eq!(ed_public_key_as_x, x_public_key);
    }
}
