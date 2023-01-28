use chrono::Utc;
use hmac::{Hmac, Mac};
use log::{info, trace, warn};
use once_cell::sync::Lazy;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

static TOKEN_KEY: Lazy<Secret<[u8; 32]>> = Lazy::new(|| Secret::new(rand::random()));

#[derive(Clone, Serialize, Deserialize)]
struct Token<'a> {
    username: &'a str,
    expiration_time: i64,
    nonce: [u8; 12],
    mac: Vec<u8>,
}

pub fn get_username_from_token_if_valid<'a>(string: &'a Secret<String>) -> Option<&'a str> {
    trace!("Decoding token");

    let token: Token<'a> = serde_json::from_str(string.expose_secret()).ok()?;

    let now = Utc::now().timestamp();

    if now > token.expiration_time {
        info!("Attempted to decode expired token");
        return None;
    }

    let mut mac_generator = Hmac::<Sha3_256>::new_from_slice(TOKEN_KEY.expose_secret()).ok()?;

    mac_generator.update(&aad(token.username, token.expiration_time, token.nonce));

    if mac_generator.verify_slice(&token.mac).is_err() {
        warn!("Someone attempted to use an invalid token");
        return None;
    }

    Some(token.username)
}

pub fn create_token(username: &str) -> Result<String, anyhow::Error> {
    trace!("Creating a token for {username}");

    // Let them last a day
    let expiration_time = Utc::now().timestamp() + 60 * 60 * 24;

    let nonce: [u8; 12] = rand::random();

    let mut mac_generator = Hmac::<Sha3_256>::new_from_slice(TOKEN_KEY.expose_secret())?;

    mac_generator.update(&aad(username, expiration_time, nonce));

    Ok(serde_json::to_string(&Token {
        username,
        expiration_time,
        nonce,
        mac: mac_generator.finalize().into_bytes().to_vec(),
    })?)
}

fn aad(username: &str, expiration_time: i64, nonce: [u8; 12]) -> Vec<u8> {
    [username.as_bytes(), &expiration_time.to_be_bytes(), &nonce].concat()
}

pub fn hash_password(password: &Secret<String>, salt: [u8; 32]) -> Vec<u8> {
    trace!("Hashing a password");

    let mut hasher = Sha3_256::new();

    hasher.update(salt);
    hasher.update(password.expose_secret());

    hasher.finalize().to_vec()
}
