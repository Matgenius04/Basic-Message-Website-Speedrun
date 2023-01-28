import { browser } from '$app/environment'

export class Accounts {
    static async storeAuthorizationString(string) {
        if (browser) window.sessionStorage.setItem("authorizationString", string)
        throw "Window object not found"
    }
    static async createAccount(username, password) {
        const res = await fetch("api/create-account", {
            method: "POST",
            body: JSON.stringify({username, password})
        })
        if (res.status == 409) return "Username Taken"
        storeAuthorizationString(await res.text())
        return "Success"
    }
    static async login(username, password) {
        const res = await fetch("api/login", {
            method: "POST",
            body: JSON.stringify({username, password})
        })
        if (res.status == 409) return "Invalid Username"
        if (res.status == 403) return "Incorrect Password"
        storeAuthorizationString(await res.text())
        return "Success"
    }
    static logout() {
        if (browser) window.sessionStorage.clear();
    }
    static loggedIn() {
        return Boolean(browser ? JSON.parse(window.sessionStorage.getItem("authorizationString"))?.expirationTime > Date.now():false);
    }
}