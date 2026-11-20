# Running the tests

The full description of every job is in [What each test covers](test-suite-map.md), and the rules for writing one are in `tests/CLAUDE.md`.

To run the docker-based tests locally, run the following commmand:
```sudo CONFIG_FILE=./env/local.js docker compose -f docker-compose-run-tests.yml up --abort-on-container-exit```
To run tests locally, run: ```./local-run-tests.sh```

If you need to pop up the browser for troubleshooting, pass in the --browser option to the test scripts.

To generate a code coverage report, run ```./run-coverage.sh```. The report will be under the coverage directory.

### The mock STS runs from its release image
Everything the suite needs on the *other* side of a protocol — the WS-Trust STS, the SAML 2.0 IdP endpoints, the OAuth 2.0 / OIDC authorization server, the OID4VCI Credential Issuer, the OID4VP Verifier, the KDC, the LDAP directory and the `did:web` document — is one Node service, [`rcbj/iya-sts`](https://github.com/rcbj/iya-sts). It used to live in `sts/` in this repository and was then linked as the `sts/` submodule; since 2026-11-13 this repository holds no copy of it. Every compose file runs its published release image — not iya-sts's public package itself but the PRIVATE copy of it in this repository's image mirror (`.github/image-mirror.txt`), which the Mirror Images workflow refreshes from iya-sts's release, like every other image the stacks pull. Pulling it needs `docker login ghcr.io` with a token that can read packages:

| What | How |
|---|---|
| the `sts` service | `image: ${IYA_STS_IMAGE:-${IMAGE_MIRROR:-ghcr.io/rcbj/id-proto-debugger/mirror}/iya-sts:<version>}` — the default in `docker-compose-run-tests.yml` is the one place the release is named, and `tests/image_mirror_coverage.js` fails when another compose file disagrees or the default is not the mirror's copy |
| its companion (demo pages, SPNEGO page, Kerberos TCP service) | built from iya-sts's repository at the matching tag into the private mirror by `.github/scripts/mirror-builds.sh`, and pulled as `${IYA_STS_COMPANION_IMAGE:-…/mirror/iya-sts-companion:v<version>}` |
| tests that load iya-sts's code in process | the tests image copies the image's `/usr/src/sts`; a host run copies it once into `~/.cache/id-proto-debugger/iya-sts/` (`tests/module_paths.js`, `iyaStsTree()`) |

Set `IYA_STS_IMAGE` to run a candidate image, or `MOCK_STS_DIR` to load a working copy of iya-sts's tree in the in-process tests. A checkout from before 2026-11-13 keeps an `sts/` directory after pulling; nothing reads it, and it can be deleted.

### The SAML SP key pair
The SAML tests sign the AuthnRequest and LogoutRequest, and decrypt an encrypted assertion, with a Service Provider key pair. **No key pair is stored in this repository.** `generateSpKeyPair()` in [`common/common.sh`](../../common/common.sh) creates a fresh self-signed RSA 2048 pair at the start of every run — in a temporary directory that is deleted as soon as the PEMs have been read — and exports it:

| Variable | What it is | Who uses it |
|---|---|---|
| `SAML_SP_PRIVATE_KEY` | the private key, PEM | the tests, via [`common/sp_keypair.js`](../../common/sp_keypair.js) — pasted into the debugger's SP key fields to sign and to decrypt |
| `SAML_SP_CERT` | the matching certificate, PEM | the tests, as the SP public key |
| `SAML_SP_SIGNING_CERT` | the same certificate as base64 DER | `configureKeycloak`, which registers it on the SAML client so Keycloak validates the request signature |

So the key exists only in the environment of the run that generated it: on the host for `./local-run-tests.sh` and `./remote-run-tests.sh`, and inside the tests container for the fully-containerized suite (`tests/run-tests-in-container.sh` generates its own, so nothing is baked into the image). The generator turns the shell's `set -x` trace off around the key material and logs only a SHA-256 fingerprint, so the private key never reaches a build log.

Running a single SAML test script by hand needs those variables in the environment — its certificate is what Keycloak was told to trust, so a self-generated pair would not validate. The scripts say so and stop if they are missing.
