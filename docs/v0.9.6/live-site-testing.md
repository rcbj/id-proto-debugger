# Testing against the deployed sites

The Selenium suite runs three ways. `./docker-run-tests.sh` builds and
runs everything in containers, which is what Selenium Tests does on
every push. `./run-coverage.sh` does the same under instrumentation.
`./remote-run-tests.sh <base-url>` runs the suite against a debugger
that is **already deployed**, such as <https://test.idptools.com> or
<https://idptools.com>, and starts locally everything on the other side
of each protocol. This page is about the third.

## What runs where

The site under test is the deployed one. Everything it talks to runs
on the machine running the suite, from `keycloak-tests.yml`, on
loopback: Keycloak 26.x on 8080, iya-sts on 8081, the Keycloak 8.0.1
WS-Federation side-car on 8082, and walt.id's issuer and verifier on
7005 and 7003. Selenium drives a local Chrome, and Chrome treats
`http://localhost` as trustworthy, so an https page may call those
services without a mixed-content block.

```bash
./remote-run-tests.sh https://test.idptools.com
# stop the stack afterwards:
sudo docker compose -p idptools-kctest -f keycloak-tests.yml down
```

It needs Docker, a local Chrome, node, curl, jq, openssl, xmllint for
the WS-Trust schema job, and MIT Kerberos (`kinit`, from `krb5-user`)
for the jobs that sign in to iya-sts by SPNEGO. Every image comes from
the private mirror on ghcr.io, so `docker login ghcr.io` first.

## The two workflows

`website-test-live.yml` runs it against test.idptools.com after each
deploy there, and `website-test-live-prod.yml` against idptools.com.
Both also run nightly. Three things about them are easy to get wrong.

* **They run master's copy of the workflow file.** A workflow started
  by another workflow finishing, or by a schedule, always uses the file
  on the default branch. A change to either workflow does nothing until
  it reaches `master`, even though the test site is deployed from
  `develop`.
* **They test the commit the site was built from.** The first step reads
  the site's `/version.json` and checks out the commit it names, so the
  tests and the deployed pages always agree, whichever branch the
  workflow file came from.
* **A manual run of either workflow may name the iya-sts
  images.** Because the checkout is the deployed commit, its compose
  defaults name that commit's iya-sts release, and a branch cannot
  change them. The `iya_sts_image` and `iya_sts_companion_image` inputs
  set `IYA_STS_IMAGE` and `IYA_STS_COMPANION_IMAGE` for the run, which is
  how a candidate is tried against the live site (empty keeps the
  defaults):

  ```bash
  gh workflow run website-test-live.yml --ref develop \
    -f iya_sts_image=ghcr.io/rcbj/id-proto-debugger/mirror/iya-sts:1.1.0-candidate \
    -f iya_sts_companion_image=ghcr.io/rcbj/id-proto-debugger/mirror/iya-sts-companion:v1.1.0-candidate
  ```

  Both images must be in the private mirror first.
* **They need the ghcr.io login and `packages: read`**, because every
  stack image is a private package, and MIT Kerberos on the runner,
  which the containerized suite gets from `tests/Dockerfile`.

## iya-sts is configured as the containerized stack configures it

`keycloak-tests.yml` gives iya-sts `CONFIG_FILE=${STS_CONFIG_FILE:-./env/test.js}`
and `STS_KEYS_EDDSA_SIGNING=true`, the same as
`docker-compose-run-tests.yml`. Both matter:

* iya-sts's `env/local.js` keeps the production sign-in limits, 20
  attempts per address and 5 per identity per minute. A pool of browser
  jobs signing in from one runner hits them, and the federation grid
  reads "Too many attempts. Wait 10 seconds and try again." `env/test.js`
  raises them to 500 and 100.
* EdDSA signing is off by default since iya-sts v1.0.0, and the UserInfo
  jobs drive it.

Until 2026-11-14 the live stack used `env/local.js` with EdDSA off, and
the live suites had been red since 2026-10-26 (test site) and
2026-11-03 (production). Both have passed since.

## What a static site does not have

The deployed sites are static: the client's pages with no api behind
them. The build (`client/static_site.js`, applied by `client/build.js`)
drops eight pages, and their landing cards are greyed out:

* the five Kerberos pages (the workflow's three steps, delegation and
  the decoder) and SPNEGO, which need a KDC on port 88;
* LDAP, whose whole protocol runs in the api;
* SPIFFE, whose gRPC surfaces a browser cannot speak.

The jobs for those pages are skipped against a static site, which is
most of the roughly forty skips in a live run. Pages that remain but
lean on the api say so on the page, and their jobs check what remains:

* the SSF page's push half, which needs the api's RFC 8935 receiver,
  is reported as not exercised;
* the smart-card page refuses every operation over CCID ("CCID needs the
  api, and this deployment has none."), and its job accepts that
  refusal and does not run the recorded-key replay
  ([smart cards](smartcard.md#tests));
* walt.id, iya-sts and Keycloak are reached from the browser directly,
  so the workflows that only need those run in full.

The build also **minifies** each page. It rewrites
`onclick="f('x', 'y')"` as `onclick='f("x","y")'`, so an in-page script
that reads an attribute must allow either quote. The containerized
suite serves the unminified pages and cannot see this. Only a live run
does.
