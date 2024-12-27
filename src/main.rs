use base64::{self, engine::general_purpose, Engine as _};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug)]
struct ThePublicKey {
    curve: String, // Name of the curve (e.g., "secp256k1")
    x: String,     // Public key's X-coordinate as a base64-encoded string
    y: String,     // Public key's Y-coordinate as a base64-encoded string
}

#[derive(Serialize, Deserialize, Debug)]
struct ThePrivateKey {
    public_key: ThePublicKey, // Public key
    d: String,                // Private key (D) as a base64-encoded string
}

#[derive(Serialize, Deserialize, Debug)]
struct Account {
    private_key: ThePrivateKey,
    address: String,
}

fn get_address(public_key: &ThePublicKey) -> String {
    let json_key = serde_json::to_string(public_key).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(json_key.as_bytes());
    let hash_result = format!("0x{:x}", hasher.finalize());

    return hash_result;
}

fn generate_new_private_key() -> ThePrivateKey {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
    println!("\n-- generating keys --");
    println!("Secret Key: {:?}", secret_key);
    println!("Public Key: {:?}", public_key);
    println!("-- end generating keys --\n");
    return serialize_keys(&secret_key, &public_key);
}

fn main() {
    let serialized = generate_new_private_key();
    let json_key = serde_json::to_string(&serialized).unwrap();

    println!("-- json --");
    println!("{}", json_key);
    println!("-- end json --\n");

    let blockchain_address = get_address(&serialized.public_key);

    println!("-- address --");
    println!("{}", blockchain_address);
    println!("-- end address --");

    // Optionally, deserialize back
    let deserialized = deserialize_keys(&serialized).expect("Failed to deserialize keys");
    println!("\n-- deserialized keys --");
    println!("Deserialized Secret Key: {:?}", deserialized.0);
    println!("Deserialized Public Key: {:?}", deserialized.1);
    println!("-- end deserialized keys --");
}

fn serialize_keys(secret_key: &SecretKey, public_key: &PublicKey) -> ThePrivateKey {
    let d = general_purpose::STANDARD.encode(secret_key.secret_bytes());

    let public_key_serialized = public_key.serialize_uncompressed();
    let x = general_purpose::STANDARD.encode(&public_key_serialized[1..33]); // X is bytes 1-32
    let y = general_purpose::STANDARD.encode(&public_key_serialized[33..]); // Y is bytes 33-64

    ThePrivateKey {
        public_key: ThePublicKey {
            curve: "secp256k1".to_string(),

            x,
            y,
        },
        d,
    }
}

fn deserialize_keys(
    serialized: &ThePrivateKey,
) -> Result<(SecretKey, PublicKey), secp256k1::Error> {
    let d_bytes = general_purpose::STANDARD
        .decode(&serialized.d)
        .expect("Invalid base64 in D");

    let secret_key = SecretKey::from_slice(&d_bytes)?;

    let x_bytes = general_purpose::STANDARD
        .decode(&serialized.public_key.x)
        .expect("Invalid base64 in X");

    let y_bytes = general_purpose::STANDARD
        .decode(&serialized.public_key.y)
        .expect("Invalid base64 in Y");

    let mut public_key_bytes = vec![0x04];

    public_key_bytes.extend_from_slice(&x_bytes);
    public_key_bytes.extend_from_slice(&y_bytes);

    let public_key = PublicKey::from_slice(&public_key_bytes)?;

    Ok((secret_key, public_key))
}
