mod authorization;
mod chat_connection;
mod db;

use authorization::{create_token, hash_password};
use db::Db;
use log::{error, info, trace, warn};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use warp::{hyper::Response, ws::Ws, Filter};

use crate::chat_connection::Message;

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    username: String,
    salt: [u8; 32],
    password_hash: Vec<u8>,
}

#[derive(Clone, Deserialize)]
struct LoginInfo {
    username: String,
    password: Secret<String>,
}

fn create_account(db: &Db, login_info: LoginInfo) -> Result<Response<String>, anyhow::Error> {
    trace!(
        "Attempting to create an account for {}",
        &login_info.username
    );

    if db.contains(&login_info.username)? {
        trace!("Attempted to create an account that already exists");

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

    info!("Created a new account for {}", &login_info.username);

    Ok(Response::builder()
        .status(200)
        .body(create_token(&login_info.username)?)?)
}

fn login(db: &Db, login_info: LoginInfo) -> Result<Response<String>, anyhow::Error> {
    trace!("Login attempt for {}", &login_info.username);

    let user = match db.get(&login_info.username)? {
        Some(user) => user,
        None => {
            trace!(
                "Login attempt failed because `{}` doesn't exist",
                &login_info.username
            );

            return Ok(Response::builder()
                .status(409)
                .body("The username doesn't exist".to_string())?);
        }
    };

    if user.password_hash != hash_password(&login_info.password, user.salt) {
        warn!(
            "Login attempt for `{}` failed because of incorrect password",
            &login_info.username
        );

        return Ok(Response::builder()
            .status(403)
            .body("The password is incorrect".to_owned())?);
    }

    info!("{} logged in", &login_info.username);

    Ok(Response::builder()
        .status(200)
        .body(create_token(&login_info.username)?)?)
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let db = Db::open("users");

    let create_account_db = db.to_owned();
    let create_account = warp::path!("api" / "create-account")
        .and(warp::body::json::<LoginInfo>())
        .map(
            move |login_info: LoginInfo| match create_account(&create_account_db, login_info) {
                Ok(reply) => Ok(reply),
                Err(e) => {
                    error!("There was an error creating an account: {e:?}");
                    Response::builder().status(500).body(e.to_string())
                }
            },
        );

    let login_db = db.to_owned();
    let login = warp::path!("api" / "login")
        .and(warp::body::json::<LoginInfo>())
        .map(
            move |login_info: LoginInfo| match login(&login_db, login_info) {
                Ok(reply) => Ok(reply),
                Err(e) => {
                    error!("There was an error logging someone in: {e:?}");
                    Response::builder().status(500).body(e.to_string())
                }
            },
        );

    let (message_tx, _) = broadcast::channel::<Message>(32);

    let ws_route = warp::path!("api" / "ws")
        .and(warp::ws())
        .and(warp::any().map(move || message_tx.to_owned()))
        .map(|ws: Ws, message_tx: broadcast::Sender<Message>| {
            ws.on_upgrade(|socket| chat_connection::chat_connection(socket, message_tx))
        });

    let get = warp::get().and(ws_route.or(warp::fs::dir("../frontend/build")));
    let post = warp::post().and(create_account.or(login));

    let routes = get.or(post);

    info!("Serving");

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
