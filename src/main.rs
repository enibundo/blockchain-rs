use base64::{self, engine::general_purpose, Engine as _};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct KeySerialization {
    curve: String, // Name of the curve (e.g., "secp256k1")
    d: String,     // Private key (D) as a base64-encoded string
    x: String,     // Public key's X-coordinate as a base64-encoded string
    y: String,     // Public key's Y-coordinate as a base64-encoded string
}

fn main() {
    let secp = Secp256k1::new();

    let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
    println!("Secret Key: {:?}", secret_key);
    println!("Public Key: {:?}", public_key);

    let serialized = serialize_keys(&secret_key, &public_key);
    println!("Serialized Keys: {:?}", serialized);

    // Optionally, deserialize back
    let deserialized = deserialize_keys(&serialized).expect("Failed to deserialize keys");
    println!("Deserialized Keys: {:?}", deserialized);

    // Verify that the deserialized keys match the original keys
    assert_eq!(secret_key, deserialized.0);
    assert_eq!(public_key, deserialized.1);
}

fn serialize_keys(secret_key: &SecretKey, public_key: &PublicKey) -> KeySerialization {
    let d = general_purpose::STANDARD.encode(secret_key.secret_bytes());

    let public_key_serialized = public_key.serialize_uncompressed();
    let x = general_purpose::STANDARD.encode(&public_key_serialized[1..33]); // X is bytes 1-32
    let y = general_purpose::STANDARD.encode(&public_key_serialized[33..]); // Y is bytes 33-64

    KeySerialization {
        curve: "secp256k1".to_string(),
        d,
        x,
        y,
    }
}

fn deserialize_keys(
    serialized: &KeySerialization,
) -> Result<(SecretKey, PublicKey), secp256k1::Error> {
    let d_bytes = general_purpose::STANDARD
        .decode(&serialized.d)
        .expect("Invalid base64 in D");
    let secret_key = SecretKey::from_slice(&d_bytes)?;

    let x_bytes = general_purpose::STANDARD
        .decode(&serialized.x)
        .expect("Invalid base64 in X");
    let y_bytes = general_purpose::STANDARD
        .decode(&serialized.y)
        .expect("Invalid base64 in Y");

    let mut public_key_bytes = vec![0x04];
    public_key_bytes.extend_from_slice(&x_bytes);
    public_key_bytes.extend_from_slice(&y_bytes);

    let public_key = PublicKey::from_slice(&public_key_bytes)?;

    Ok((secret_key, public_key))
}
