use chrono::Utc;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

static TOKEN_KEY: Lazy<[u8; 32]> = Lazy::new(rand::random);

#[derive(Clone, Serialize, Deserialize)]
struct Token<'a> {
    username: &'a str,
    expiration_time: i64,
    nonce: [u8; 12],
    mac: Vec<u8>,
}

pub fn get_username_from_token_if_valid<'a>(string: &'a str) -> Option<&'a str> {
    let token: Token<'a> = serde_json::from_str(string).ok()?;

    let now = Utc::now().timestamp();

    if now > token.expiration_time {
        return None;
    }

    let mut mac_generator = Hmac::<Sha3_256>::new_from_slice(&*TOKEN_KEY).ok()?;

    mac_generator.update(&aad(token.username, token.expiration_time, token.nonce));

    mac_generator.verify_slice(&token.mac).ok()?;

    Some(token.username)
}

pub fn create_token<'a>(username: &'a str) -> Result<String, anyhow::Error> {
    // Let them last a day
    let expiration_time = Utc::now().timestamp() + 60 * 60 * 24;

    let nonce: [u8; 12] = rand::random();

    let mut mac_generator = Hmac::<Sha3_256>::new_from_slice(&*TOKEN_KEY)?;

    mac_generator.update(&aad(&username, expiration_time, nonce));

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

pub fn hash_password(password: &str, salt: [u8; 32]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();

    hasher.update(salt);
    hasher.update(password);

    hasher.finalize().to_vec()
}
