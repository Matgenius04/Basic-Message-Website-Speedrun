The server will give a 400 error for any requests that are formatted wrong.

# Accounts

## Creating an account

Post the server a JSON object formatted as below to the route `/api/create-account`:

```
  {
    username: string,
    password: string,
  }
```

The server will give a `409` error if the username already exists, otherwise it will give an authorization string.

## Logging in

Post the server a JSON object formatted as below to the route `/api/login`:

```
  {
    username: string,
    password: string,
  }
```

The server will give a `409` error if the username doesn't exist or a `403` error if the password is incorrect. Otherwise it will give an authorization string.

## Authorization string

This is a string formatted as:

```
  {
    username: string,
    expirationTime: number,
    nonce: number[],
    mac: number[],
  }
```

The string does not need to be parsed, and must be given back to the server verbatim whenever authorization is needed.

# Chat

Send a websocket upgrade request to `/api/ws`. Then send a message formatted as:

```
  {
    authorization: Authorization string
  }
```

If the authorization is incorrect, the server will close the connection.

The server will send messages formatted as:

```
  {
    author: string,
    message: string,
  }
```

To broadcast a message, send a message formatted as:

```
  {
    message: string
  }
```