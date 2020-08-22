# Wireguard Key Management
This project is a Flask application that allows management of keys by users for a Wireguard VPN system. Users can log in using popular OAuth methods such as Google and Twitter and add public keys to a system's Wireguard configuration without interaction from system administrators.

In addition to this, built into the application is a method of requiring authentication before allowing connection to Wireguard. This is done via "Connection Requests", where the Wireguard service will send a request to the application to check whether the user has accepted the connection request. This requires the user to have logged in via their OAuth account and accept the connection request, before the user can connect. This adds another method of authentication to the VPN in addition to their private key.

The flow for connection requests looks something like this:

1. User attempts to connect to their Wireguard server (using `wg-quick up foobar` for example)
2. Foobar's wireguard server sends a HTTP request to the application, telling the application this user is attempting to connect to the server.
3. The application sends a push notification (via Google's Firebase Cloud Messaging) to alert the user that there is a pending connection request.
4. The user logs into the application (and will be asked to re-login if they are already logged in) and accept the connection request.
5. The next time the Wireguard server sends a HTTP request, the application will send a payload containing `"authorised": true`, in which the Wireguard application will then accept the request and complete the handshake.

The interception of the handshake packet can be done in a variety of ways such as a UDP proxy, which will inspect the packet and send the request on behalf of the Wireguard application, or running a custom Wireguard installation which sends the web request when handling the handshake.