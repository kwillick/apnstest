# apnstest

This is for testing [apns](https://github.com/kwillick/apns).

### Config
The server requires three files:

1.  A root certificate.
2.  A certificate signed by the root certificate.
3.  A private key that pairs with 2.

The client also requires three files:

1.  The same root certificate as the server.
2.  A certificate signed by the root certificate.
3.  A private key that pairs with 2.

### Server
The server pretends to be the Apple side of push notification sending.
When it receives push notification data, it prints it to stdout.

### Client
The client connects to the server and tries to send 10 push notifications.

