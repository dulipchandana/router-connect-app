# App functionality

This Expo/React Native project provides a small web UI for testing the login
session flow of a locally accessible Nokia router. On the web app, switching
ON and OFF check the session and submit a guest Wi-Fi configuration for
`NOKIA-45AA_Guest`. The button is then refreshed from the router's status
response.

## Startup and session handling

In the web app, a cached login session is loaded from browser `localStorage`.
When a cached session ID is available, the app calls the local proxy's
`/check-expire` endpoint to ask the router whether that session is still valid:

- If the router reports `expired: "no"` and provides a positive `expire` value,
  the app keeps the cache and requests the guest Wi-Fi status. The button is ON
  only when every matching `NOKIA-45AA_Guest` WLAN entry has `Enable` set to `1`.
- If the router reports an expired session, or the cache is missing, the app
  performs the login flow below and saves the resulting session data.
- If a session check fails, the error is displayed in the UI. A failed check
  of an existing cache also causes the app to attempt a fresh login.

The app also monitors the session while a session ID is cached. Monitoring
starts with an immediate check; after a valid check, the next check is scheduled
for `expire` seconds multiplied by 500 milliseconds (approximately half the
reported remaining lifetime), with a minimum delay of one second. An expired
session triggers a fresh login. Because startup validation and monitoring are
separate, a cached session can cause two checks close together on reload.

## Login flow

The web app sends router requests through the local Node proxy:

1. **`/nonce`** — the proxy forwards a POST to
   `login_web_app.cgi?nonce` with the configured username. The router returns a
   nonce, random key, iteration count, and potentially a public key.
2. **`/salt`** — the app calculates a username-and-nonce hash, then the proxy
   forwards a POST to `login_web_app.cgi?salt` with `userhash` and `nonce`. The
   router returns the salt.
3. **`/response`** — this is a local calculation, not a router request. The
   proxy uses the salt, nonce, iteration count, and configured router password
   to calculate the challenge response. It also generates an encryption key
   and IV.
4. **`/login`** — the proxy forwards a POST to `login_web_app.cgi` with the
   generated `userhash`, `randomkeyhash`, `response`, `nonce`, `enckey`, and
   `enciv` fields. The router returns a session ID and may return a token.
5. **`/check-expire`** — the proxy forwards a request to
   `check_expire_web_app.cgi` using the session ID to check whether the session
   is valid and how long it has left.

The app shows the full login response JSON, including `sid` and `token`, and
generated hashes and values on screen for inspection. Session check output
redacts sensitive values. Treat the displayed login response and generated
values as sensitive; anyone with access to the browser can reuse the session
until it expires.

## Guest Wi-Fi request

When the button is switched ON or OFF, the app checks the cached session first.
If that check shows the session has expired, the app logs in again and retries
with the new session. It then asks the local proxy's `/guest-config` endpoint
to GET `wlan_config_guest_status_web_app.cgi` using the current session ID as
the `sid` cookie. It uses the first guest mapping's `MappedWlanIdx` to read the
guest SSID and password from `wlan_list`, then constructs the same form payload
as the Nokia web page: action, enable state, SSID, password, band/sync options,
and CSRF token. It does not send `wlan_list` or `guest_list` JSON in the
encrypted payload.

For this router's web UI profile, the form uses `dual_band=0`, an empty
`ssid_num`, `sync_value=false`, and `wpa3_support=1`. The app generates a
random AES key and IV, encrypts the payload with AES-128-CBC, and wraps the
key/IV with the cached router public key using RSA PKCS#1 v1.5. The app creates
`encrypted`, `ct`, and `ck` locally and sends only those encrypted fields to
`/wifi-config`. The proxy forwards the request using the `wifi-on.json`
endpoint and current `sid` cookie for either toggle state; captured ciphertext
is never replayed. The settings response is shown with password/token/session fields
redacted, and the generated ciphertext and router response are displayed for
inspection.

After the router confirms the configuration response with `result: 0` and
`reason: 0`, the app makes another GET using the request in
`postman-wifi-status.json` and the cached session ID as the `sid` cookie. That
status response determines the button state: it is ON only when all matching
`NOKIA-45AA_Guest` WLAN entries have `Enable` equal to `1`; otherwise it is
OFF. The same status request runs on app startup after the cached session is
validated (or after a new login).

Guest Wi-Fi settings and status JSON show `PreSharedKey` values as returned by
the router. Other password, token, session ID, and CSRF token fields remain
redacted in those displays. Treat the visible Wi-Fi keys as sensitive.

`wifi-on.json` is retained as the endpoint/header template, not as the source
of ciphertext.

## Local proxy

The browser app talks to `http://127.0.0.1:3001`; the proxy forwards requests to
the router at the address configured in the Postman JSON collections. The proxy
accepts requests only from its configured web origins and validates request
paths and payloads.

Start the proxy from the project directory:

```sh
npm run proxy
```

Then start the web app in another terminal:

```sh
npm run web
```

Router credentials are read locally by the proxy from
`router-credentials.local.json`. Keep that file and any proxy output private.
The app's browser cache is stored in `localStorage`; clearing the site's
browser storage removes the cached session.

The challenge-response calculation is implemented for the web app through the
local proxy. Native iOS/Android builds do not complete this flow as currently
implemented.

## Configuration files

- `wifi-login.json` — nonce request definition and configured username.
- `wifi-log-salt.json` — salt request definition.
- `postman-hash.json` — login request definition.
- `chek-cgi.json` — session-expiration request definition.
- `postman-wifi-status.json` — guest Wi-Fi status request definition.
- `wifi-on.json` — guest Wi-Fi configuration request template; captured
  ciphertext is not replayed.
- `router-credentials.local.json` — local router username and password used by
  the proxy.
- `proxy-server.cjs` — local proxy routes, request validation, and response
  calculation.
- `App.tsx` — UI, browser cache, login sequence, and session monitoring.
