//! Asymmetric keypair generation. X25519 for account / org key wrapping;
//! Ed25519 for signatures arrives in a later milestone.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// 32 random bytes, ready for use as a CSPRNG-generated symmetric key.
pub fn random_key_32() -> Zeroizing<[u8; 32]> {
    use rand::RngCore;
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// Generate an X25519 keypair. Returns `(secret_bytes, public_bytes)` —
/// the secret is in `Zeroizing` so it wipes on drop.
pub fn generate_x25519() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let secret_bytes = Zeroizing::new(secret.to_bytes());
    (secret_bytes, public.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_yields_distinct_keypairs() {
        let (s1, p1) = generate_x25519();
        let (s2, p2) = generate_x25519();
        assert_ne!(s1.as_ref(), s2.as_ref());
        assert_ne!(p1, p2);
    }

    #[test]
    fn random_key_is_32_bytes_and_nonzero() {
        let k = random_key_32();
        assert_eq!(k.len(), 32);
        assert!(k.iter().any(|b| *b != 0));
    }
}
