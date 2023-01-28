use aes_gcm_siv::{
    aead::{Aead, Payload},
    Aes256GcmSiv, Key, KeyInit, Nonce,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

static TOKEN_KEY: Lazy<Key<Aes256GcmSiv>> =
    Lazy::new(|| *Key::<Aes256GcmSiv>::from_slice(&rand::random::<[u8; 32]>()));

#[derive(Clone, Serialize, Deserialize)]
struct Token {
    username: String,
    expiration_time: i64,
    nonce: [u8; 12],
    token: Vec<u8>,
}

impl Token {
    pub fn decode_if_valid(string: &str) -> Option<Token> {
        let token: Self = serde_json::from_str(string).ok()?;

        let now = Utc::now().timestamp();

        if now > token.expiration_time {
            return None;
        }

        let aes = Aes256GcmSiv::new(&*TOKEN_KEY);

        let _ = aes
            .decrypt(
                Nonce::from_slice(&token.nonce),
                Payload {
                    msg: &token.token,
                    aad: &Token::aad(&token.username, token.expiration_time, token.nonce),
                },
            )
            .ok()?;

        Some(token)
    }

    pub fn create(username: String) -> Result<Token, aes_gcm_siv::Error> {
        // Let them last a day
        let expiration_time = Utc::now().timestamp() + 60 * 60 * 24;

        let nonce: [u8; 12] = rand::random();

        let random_data: [u8; 32] = rand::random();

        let aes = Aes256GcmSiv::new(&*TOKEN_KEY);

        let token = aes.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &random_data,
                aad: &Token::aad(&username, expiration_time, nonce),
            },
        )?;

        Ok(Token {
            username,
            expiration_time,
            nonce,
            token,
        })
    }

    fn aad(username: &str, expiration_time: i64, nonce: [u8; 12]) -> Vec<u8> {
        [username.as_bytes(), &expiration_time.to_be_bytes(), &nonce].concat()
    }
}
