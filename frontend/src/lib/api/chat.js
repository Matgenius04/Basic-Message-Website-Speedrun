import { browser } from "$app/environment"
import { messages } from "./stores"

let authorizationString = browser ? window.sessionStorage.getItem("authorizationString") : ''

if (!authorizationString) console.error("No Authorization String Found")

const ws = new WebSocket("/api/ws")
ws.onopen(ev => {
    this.send(authorizationString);
})
ws.onmessage(ev => {
    messages.update(previousMessages => (previousMessages.push(ev.data), previousMessages))
})