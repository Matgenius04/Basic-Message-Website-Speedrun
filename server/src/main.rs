use futures::StreamExt;
use tokio::sync::broadcast;
use warp::{ws::Ws, Filter};

#[derive(Clone)]
struct Message {
    author: String,
    message: String,
}

#[tokio::main]
async fn main() {
    let (tx, rx) = broadcast::channel::<Message>(32);

    let ws_route = warp::path("ws").and(warp::ws()).map(|ws: Ws| {
        ws.on_upgrade(|socket| async {
            let (mut tx, mut rx) = socket.split();

            while let Some(maybe_message) = rx.next().await {
                let message = match maybe_message {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };
            }
        })
    });

    let routes = warp::get().and(ws_route);

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
