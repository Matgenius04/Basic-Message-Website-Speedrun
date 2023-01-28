mod authorization;
mod db;

use authorization::{hash_password, Token};
use db::Db;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use warp::{hyper::Response, ws::Ws, Filter};

#[derive(Clone, Serialize, Deserialize)]
struct Message {
    author: String,
    message: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    username: String,
    salt: [u8; 32],
    password_hash: [u8; 32],
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

    let password_hash = hash_password(&login_info.password, salt)?;

    let user = User {
        username: login_info.username,
        salt,
        password_hash,
    };

    db.add(user)?;

    Ok(Response::builder()
        .status(200)
        .body(Token::create(login_info.password)?)?)
}

#[tokio::main]
async fn main() {
    let db = Db::open("users");

    let create_account = warp::path!("api" / "create-account")
        .and(warp::body::json::<LoginInfo>())
        .map(
            move |login_info: LoginInfo| match create_account(&db, login_info) {
                Ok(reply) => Ok(reply),
                Err(e) => Response::builder().status(500).body(e.to_string()),
            },
        );

    let (tx, rx) = broadcast::channel::<Message>(32);

    let ws_route = warp::path!("api" / "ws").and(warp::ws()).map(|ws: Ws| {
        ws.on_upgrade(|socket| async {
            let (mut tx, mut rx) = socket.split();

            while let Some(maybe_message) = rx.next().await {
                let message = match maybe_message {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };

                let text = match message.to_str() {
                    Ok(v) => v,
                    Err(e) => continue,
                };

                let message: Message = match serde_json::from_str(text) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };
            }
        })
    });

    let get = warp::get().and(ws_route.or(warp::fs::dir("../frontend/build")));
    let post = warp::post().and(create_account);

    let routes = get.or(post);

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
