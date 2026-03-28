use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::random;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keypair {
    verifying_key: [u8; 32],
    signing_key: [u8; 32],
}

impl Keypair {
    pub fn generate() -> Keypair {
        let signing_key_bytes: [u8; 32] = random();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signing_key = signing_key.to_bytes();

        Keypair {
            verifying_key,
            signing_key
        }
    }

    pub fn from_signing_key_bytes(signing_key_bytes: [u8; 32]) -> Keypair {
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signing_key = signing_key.to_bytes();

        Keypair {
            verifying_key,
            signing_key,
        }
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key
    }

    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.signing_key);
        signing_key.sign(message).to_bytes()
    }
}

pub fn verify_signature(
    verifying_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(verifying_key_bytes) else {
        return false;
    };

    let signature = Signature::from_bytes(signature_bytes);
    verifying_key.verify(message, &signature).is_ok()
}
