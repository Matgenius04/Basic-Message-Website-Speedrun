mod authorization;

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use warp::{ws::Ws, Filter};

#[derive(Clone, Serialize, Deserialize)]
struct Message {
    author: String,
    message: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    username: String,
    password_hash: [u8; 32],
}

#[tokio::main]
async fn main() {
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

    let routes = warp::get().and(ws_route);

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
