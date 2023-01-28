mod authorization;
mod db;

use std::sync::Arc;

use authorization::{create_token, get_username_from_token_if_valid, hash_password};
use db::Db;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{
    select,
    sync::broadcast::{self, error::RecvError},
};
use warp::{
    hyper::Response,
    ws::{self, Ws},
    Filter,
};

#[derive(Clone, Serialize)]
struct Message {
    author: Arc<str>,
    message: Arc<str>,
}

#[derive(Clone, Deserialize)]
enum WebsocketSignal {
    Authorization(String),
    Message(String),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    username: String,
    salt: [u8; 32],
    password_hash: Vec<u8>,
}

#[derive(Clone, Deserialize)]
struct LoginInfo {
    username: String,
    password: String,
}

fn create_account(db: &Db, login_info: LoginInfo) -> Result<Response<String>, anyhow::Error> {
    if db.contains(&login_info.username)? {
        return Ok(Response::builder()
            .status(409)
            .body("The username already exists".to_owned())?);
    }

    let salt = rand::random::<[u8; 32]>();

    let password_hash = hash_password(&login_info.password, salt);

    let user = User {
        username: login_info.username.to_owned(),
        salt,
        password_hash,
    };

    db.add(&user)?;

    Ok(Response::builder()
        .status(200)
        .body(create_token(&login_info.username)?)?)
}

fn login(db: &Db, login_info: LoginInfo) -> Result<Response<String>, anyhow::Error> {
    let user = match db.get(&login_info.username)? {
        Some(user) => user,
        None => {
            return Ok(Response::builder()
                .status(409)
                .body("The username doesn't exist".to_string())?)
        }
    };

    if user.password_hash != hash_password(&login_info.password, user.salt) {
        return Ok(Response::builder()
            .status(403)
            .body("The password is incorrect".to_owned())?);
    }

    Ok(Response::builder()
        .status(200)
        .body(create_token(&login_info.username)?)?)
}

#[tokio::main]
async fn main() {
    let db = Db::open("users");

    let create_account_db = db.to_owned();
    let create_account = warp::path!("api" / "create-account")
        .and(warp::body::json::<LoginInfo>())
        .map(
            move |login_info: LoginInfo| match create_account(&create_account_db, login_info) {
                Ok(reply) => Ok(reply),
                Err(e) => Response::builder().status(500).body(e.to_string()),
            },
        );

    let login_db = db.to_owned();
    let login = warp::path!("api" / "login")
        .and(warp::body::json::<LoginInfo>())
        .map(
            move |login_info: LoginInfo| match login(&login_db, login_info) {
                Ok(reply) => Ok(reply),
                Err(e) => Response::builder().status(500).body(e.to_string()),
            },
        );

    let (message_tx, _) = broadcast::channel::<Message>(32);

    let ws_route = warp::path!("api" / "ws")
        .and(warp::ws())
        .and(warp::any().map(move || message_tx.to_owned()))
        .map(|ws: Ws, message_tx: broadcast::Sender<Message>| {
            ws.on_upgrade(move |mut socket| async move {
                let message_tx = message_tx.to_owned();
                let mut message_rx = message_tx.subscribe();

                let mut username = None;

                loop {
                    select! {
                        maybe_message_option = socket.next() => {
                            let maybe_message = match maybe_message_option {
                                Some(v) => v,
                                None => break,
                            };

                            let message = match maybe_message {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("{e}");
                                    continue;
                                }
                            };

                            let text = match message.to_str() {
                                Ok(v) => v,
                                Err(_) => continue,
                            };

                            let signal: WebsocketSignal = match serde_json::from_str(text) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("{e}");
                                    continue;
                                }
                            };

                            match (signal, &username) {
                                (WebsocketSignal::Authorization(auth_string), None) => {
                                    username = match get_username_from_token_if_valid(&auth_string) {
                                        Some(username) => Some(Arc::from(username)),
                                        None => break
                                    }
                                }
                                (WebsocketSignal::Message(message), Some(username)) => {
                                    let _ = message_tx.send(Message {
                                        author: Arc::clone(username),
                                        message: Arc::from(message),
                                    });
                                }
                                _ => break
                            }
                        }

                        maybe_sent_message = message_rx.recv() => {
                            let sent_message = match maybe_sent_message {
                                Ok(v) => v,
                                Err(RecvError::Closed) => break,
                                Err(RecvError::Lagged(amt)) => {
                                    eprintln!("Receiver lagged by {amt} messages");
                                    continue
                                },
                            };

                            if let Err(e) = socket.send(ws::Message::text(match serde_json::to_string(&sent_message) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("{e}");
                                    continue
                                }
                            })).await {
                                eprintln!("{e}");
                                continue
                            }
                        }
                    };
                }
            })
        });

    let get = warp::get().and(ws_route.or(warp::fs::dir("../frontend/build")));
    let post = warp::post().and(create_account.or(login));

    let routes = get.or(post);

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
