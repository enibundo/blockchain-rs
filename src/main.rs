use base64::{self, engine::general_purpose, Engine as _};
use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug)]
struct SerializedPublicKey {
    curve: String,
    x: String,
    y: String,
}

impl SerializedPublicKey {
    fn get_address(&self) -> String {
        let json_key = serde_json::to_string(&self).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(json_key.as_bytes());
        let hash_result = format!("0x{:x}", hasher.finalize());

        hash_result
    }
}

#[derive(Serialize, Deserialize, Debug)]

struct SerializedPrivateKey {
    public_key: SerializedPublicKey,
    d: String,
}

struct PrivateKey {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl PrivateKey {
    fn new() -> PrivateKey {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());

        PrivateKey {
            secret_key,
            public_key,
        }
    }

    fn as_serialized(&self) -> SerializedPrivateKey {
        let d = general_purpose::STANDARD.encode(self.secret_key.secret_bytes());

        let public_key_serialized = self.public_key.serialize_uncompressed();
        let x = general_purpose::STANDARD.encode(&public_key_serialized[1..33]); // X is bytes 1-32
        let y = general_purpose::STANDARD.encode(&public_key_serialized[33..]); // Y is bytes 33-64

        SerializedPrivateKey {
            public_key: SerializedPublicKey {
                curve: String::from("secp256k1"),
                x,
                y,
            },
            d,
        }
    }

    fn sign(&self, s: &String) -> (Message, Signature) {
        let digest = sha256::Hash::hash(s.as_bytes());
        let message = Message::from_digest(digest.to_byte_array());

        (message, self.secret_key.sign_ecdsa(message))
    }

    fn to_string(&self) -> String {
        serde_json::to_string(&self.as_serialized()).unwrap()
    }

    fn get_address(&self) -> String {
        self.as_serialized().public_key.get_address()
    }
}

fn main() {
    let new_private_key = PrivateKey::new();
    let string_private_key = new_private_key.to_string();
    print_with_separator("json", &string_private_key);

    let blockchain_address = new_private_key.get_address();
    print_with_separator("address", &blockchain_address);

    let message_to_sign = String::from("Hello World");
    let (message, signature) = new_private_key.sign(&message_to_sign);

    print_with_separator("message to sign", &message_to_sign);
    print_with_separator("signed message", &signature.to_string());

    let is_valid_signature = signature
        .verify(&message, &new_private_key.public_key)
        .is_ok();

    print_with_separator("is valid signature", &is_valid_signature.to_string());
}

fn print_with_separator(title: &str, message: &str) {
    println!("-- {title} --");
    println!("{}", message);
    println!("-- end {title} --");
}
