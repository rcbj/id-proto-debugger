# Privacy and security

This project is built with your privacy and security as a priority. There is, however, one consequence of how the public site is hosted that you should be aware of.

The public site (for example, the hosted `idptools.com` / `test.idptools.com` deployments) is served as **static content** — there is no application backend. Because of this, when your Identity Provider redirects back to the debugger, the **authorization code** (along with the other OAuth2/OIDC response parameters and the redirect URI) is delivered to the debugger page *through the static hosting provider* as part of the normal page request. This is an unavoidable property of a static, backend-less build of an OAuth2/OIDC client.

To be clear about what we do with that data:

* **We do not log** any of the query parameters, fragments, authorization codes, tokens, or redirect URIs that are sent to the site as part of normal debugger operations.
* All token handling, decoding, and validation happens **client-side in your browser**; your configuration is stored only in your browser's `localStorage`.

If sending authorization codes to a third-party hosting provider is not acceptable for your use case (for example, when testing against a production Identity Provider), we strongly encourage you to **run a local build of the debugger** so that nothing leaves your machine. See [Getting started](getting-started.md). In short:

```bash
./generate-tls-cert.sh                 # once per checkout: the TLS pair
sudo CONFIG_FILE=./env/local.js docker-compose up
```

Then use the debugger at `https://localhost:3000`, and register `https://localhost:3000/callback` as your redirect URI with your Identity Provider. The services present a leaf from a local issuing CA. `./generate-tls-cert.sh` creates the root once and reuses it, and prints that root's SHA-256 fingerprint first. Trust the root. A later run issues a new leaf from the same root, so the browser keeps that trust. `--rotate-ca` starts a new root. In a local build, the authorization code is delivered to the debugger running on your own machine and never transits a third-party host.
