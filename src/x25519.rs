use zeroize::Zeroize;

pub const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

use crate::backend::x25519 as scalarmult;

/// X25519 secret key.
#[derive(Clone, Zeroize)]
pub struct SecretKey([u8; 32]);

/// X25519 public key.
#[derive(Clone, Debug)]
pub struct PublicKey([u8; 32]);

/// X25519 keypair.
#[derive(Clone)]
pub struct Keypair {
    /// Public key of the keypair.
    pub public: PublicKey,
    /// Secret key of the keypair.
    pub secret: SecretKey,
}

/// Shared secret of ECDH key agreement.
#[derive(Clone, Zeroize)]
pub struct SharedSecret([u8; 32]);

impl SecretKey {
    #[cfg(feature = "rand")]
    /// Generate a random `SecretKey`.
    pub fn random(rng: impl rand_core::CryptoRng + rand_core::RngCore) -> Self {
        let mut secret = SecretKey([0; 32]);
        let mut rng = rng;
        rng.fill_bytes(&mut secret.0);

        // Clamp key.
        secret.0[0] &= 248;
        secret.0[31] &= 127;
        secret.0[31] |= 64;

        secret
    }

    /// Create private key from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let key = Self(*bytes);

        // Check clamping.
        if key.0[0] & 248 == key.0[0] && key.0[31] & 127 == key.0[31] && key.0[31] & 64 == 64 {
            Some(key)
        } else {
            None
        }
    }

    /// Convert the key to bytes. `unsafe` as it's up to the user to not leak it.
    pub unsafe fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Calculate associated public key.
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(scalarmult(&self.0, &BASEPOINT))
    }

    /// ECDH key agreement.
    #[inline]
    pub fn agree(&self, other: &PublicKey) -> SharedSecret {
        SharedSecret(scalarmult(&self.0, &other.0))
    }
}

impl PublicKey {
    /// Make a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }

    /// Convert public key to bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Keypair {
    #[cfg(feature = "rand")]
    /// Generate a random `Keypair`.
    pub fn random(rng: impl rand_core::CryptoRng + rand_core::RngCore) -> Self {
        let secret = SecretKey::random(rng);
        let public = secret.public_key();

        Keypair { public, secret }
    }
}

impl SharedSecret {
    /// Convert shared to bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
