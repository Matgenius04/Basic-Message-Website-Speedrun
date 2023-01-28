use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use log::{error, info, trace, warn};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use tokio::{
    select,
    sync::broadcast::{self, error::RecvError},
};
use warp::ws::{self, WebSocket};

use crate::authorization::get_username_from_token_if_valid;

#[derive(Clone, Serialize)]
pub struct Message {
    author: Arc<str>,
    message: Arc<str>,
}

#[derive(Clone, Deserialize)]
enum WebsocketSignal {
    Authorization(Secret<String>),
    Message(String),
}

pub async fn chat_connection(mut socket: WebSocket, message_tx: broadcast::Sender<Message>) {
    trace!("Someone made a websocket connection");

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
                        error!("Recieving a websocket message failed: {e}");
                        continue;
                    }
                };

                let text = match message.to_str() {
                    Ok(v) => v,
                    Err(_) => {
                        trace!("Someone sent a websocket message that isn't a string");
                        continue;
                    },
                };

                let signal: WebsocketSignal = match serde_json::from_str(text) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!("Someone sent a websocket message that can't be decoded as a signal: {e}");
                        continue;
                    }
                };

                match (signal, &username) {
                    (WebsocketSignal::Authorization(auth_string), None) => {
                        username = match get_username_from_token_if_valid(&auth_string) {
                            Some(username) => {
                                info!("{username} authenticated for the chatroom");
                                Some(Arc::from(username))
                            },
                            None => {
                                warn!("Someone failed to authenticate the websocket");
                                break
                            }
                        }
                    }
                    (WebsocketSignal::Message(message), Some(username)) => {
                        info!(target: "chat", "<{username}> {message}");

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
                        warn!("Receiver lagged by {amt} messages");
                        continue
                    },
                };

                if let Err(e) = socket.send(ws::Message::text(match serde_json::to_string(&sent_message) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Failed to encode a message as json {e}");
                        continue
                    }
                })).await {
                    error!("All of the senders dropped: {e}");
                    continue
                }
            }
        };
    }
}
