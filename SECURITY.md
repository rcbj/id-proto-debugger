# Security policy

## Reporting a vulnerability

Report a vulnerability privately to the owner of this repository. Do not open a
public issue for one.

## This is a Debugger
This tool can be useful for troubleshooting Identity Provider configuration issues; however, it should never be installed in a production environment.

Most users simply startup the dockerized version of the debugger on their local device.

## Publicly Accessible Hosted Sites
The [IDPTools.com](https://idptools.com) is a static content website; there is no backend API endpoints that need to be secured.

This creates potential complications with CORS. Depending on the Identity Provdier, it may be necessary to run the containerized version of this application on your local device so that requests can be proxied through the bundled API layer.

## SSRF

This project intentionally accepts arbitrary Identity Provider endpoints because that is the core purpose of the debugger.

The project does **not** maintain an allow-list of trusted identity providers.

Instead, SSRF mitigations focus on preventing abuse:

* Only HTTP/HTTPS
* block private and loopback ranges
* request timeouts
* response size limits

Only point this protocol debugger at Identity Providers that you trust.

## How quickly a vulnerable dependency is remediated

This is the patching policy ASVS 5.0.0 requirement 15.1.1 asks for, the same
one IYA STS follows. It covers every third-party component this project ships,
directly or transitively: the npm packages of the api, the client and the test
suite, the Node runtime and the operating-system packages in the published
images, and the GitHub Actions the workflows use.

| Severity of the advisory | Remediated within |
|---|---|
| Critical | 7 days |
| High | 30 days |
| Moderate | 90 days |

* The clock starts when the advisory is **published**, not when someone next
  looks.
* Every direct dependency is reviewed for an update at least every **90 days**,
  whether or not there is an advisory against it. A package another one pulls in
  moves with its parent, and is held to the advisory windows above.
* Remediated means upgraded, removed, or shown not to be reachable from this
  project, with the reasoning recorded on a ticket.
* The debugger's intended behaviours — accepting an arbitrary identity
  provider's endpoints, or turning certificate validation off for a self-signed
  test server — are not dependency exceptions.

### How it is kept

Dependabot (`.github/dependabot.yml`) checks the api's, the client's and the
test suite's npm packages and the GitHub Actions every week, and raises a pull
request for an update or an advisory. The Node runtime is pinned to an exact
version in every image and moved deliberately, as it was to 24.22.1 for
CVE-2026-111497.

This repository does **not** yet have the automated window check IYA STS runs
(`tests/tools/dependency-windows.js` there, on every CI run and daily against
the published image), so nothing here fails a build when an advisory passes its
window. Until it does, the windows are met by acting on Dependabot's alerts and
pull requests. The client image installs exactly what its lockfile names
(`npm ci`); the api image runs `npm install` against its lockfile, which can
resolve a newer version than the lockfile records.
