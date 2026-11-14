# Releases, versions and images

How a build is numbered, what a `master` build publishes, and how a
release is cut. The workflows are `.github/workflows/dockerimage.yml`
(Docker Image CI), `tests.yml` (Selenium Tests),
`website-deploy-test.yml` and `website-deploy.yml` (the two static
sites), and `website-test-live.yml` and `website-test-live-prod.yml`
(the suite against each deployed site).

## The version

A build's version is **M.N.P.B**. `M.N.P` is the repository-root
`VERSION` file. `B` is the build number: `BUILD_NUMBER` when it is set,
which is how CI fixes one number for a whole run, and otherwise the UTC
build instant as `YYYYMMDDHHMMSS`. `client/version.js` is the one
implementation of the scheme; the api image, the client image, the
embedded build and the browser extension all call it.

```bash
node client/version.js --json
# { "version": "0.9.3.20261114152912", "release": "0.9.3", "build": "20261114152912", ... }
```

The version is stamped into each image's `version.json` at build time.
A running client shows it in the page footer and at `/version.json`,
and the deployed sites publish theirs the same way
(<https://test.idptools.com/version.json>,
<https://idptools.com/version.json>), with the commit they were built
from.

The three `package.json` files (`api`, `client`, `tests`) carry `M.N.P`.
`node client/version.js --sync-manifests` rewrites them from `VERSION`,
and `--check-manifests` fails when one has drifted.

## What a build of `master` publishes

Every push to `master` runs Docker Image CI, which builds the api, the
client and the embedded debugger and then, from `master` only:

* **Images**, public, with the same tags on both registries:

  | GitHub Container Registry | Docker Hub |
  |---|---|
  | `ghcr.io/rcbj/id-proto-debugger-api` | `iyasec/id-proto-debugger-api` |
  | `ghcr.io/rcbj/id-proto-debugger-client` | `iyasec/id-proto-debugger-client` |
  | `ghcr.io/rcbj/id-proto-debugger-embedded` | `iyasec/id-proto-debugger-embedded` |

  Each is tagged `M.N.P.B` and `latest`. The embedded image is
  `FROM scratch` and holds only the built tree that IYA STS's own image
  copies in; it is not run by itself.
* **Git tags.** `M.N.P.B` on the commit, created once and never moved,
  whose message names the images. `M.N.P`, a floating tag force-moved to
  the newest build of that line.
* **A GitHub release**, on the first `master` build of a line only:
  the tag `release-M.N.P` is created on that commit and never moved, and
  the release is titled "Release M.N.P" and marked Latest. Its notes
  list every published image with its digest, the commit, and GitHub's
  generated list of what was merged since the previous `release-*`
  tag. A later build of the same line finds the release and leaves it
  alone; a new release is a new `VERSION`. The series runs back through
  `release-0.9.2`, `release-0.9.1`, `release-0.9` and `release-0.8`,
  which were made by hand; `release-0.9.3` was the first made by the
  workflow.

The step that creates the release can be re-run. If GitHub's API fails
part-way, as it did with a 502 on the first 0.9.3 build, re-running the
failed job finds the tag it already pushed and creates the release from
it. Re-running rebuilds and republishes the images under a new build
number, and the release notes list that build.

`develop` and pull requests **build** the images, so a Dockerfile that
breaks is caught there, but publish nothing. Until 2026-10-02 `develop`
published under a floating `develop` tag; that tag is no longer
updated.

A new package on ghcr.io starts **private** even though the OCI
`source` label links it to this public repository. Make it public once
under the package's settings, Danger Zone, Change visibility; later
pushes keep the setting.

## The test stack's images

Separate from all of the above. Selenium Tests builds the stack it
tests (api, client, sts, tests, keycloak-wsfed, shibboleth-idp) and
pushes it to the **private** namespace
`ghcr.io/rcbj/id-proto-debugger/<name>`, tagged with the commit and the
branch, as a record of what each run tested. Nothing pulls those tags
back; every run builds its own. The third-party images and base images
the stack uses come from private copies under
`ghcr.io/rcbj/id-proto-debugger/mirror/`, filled by the Mirror Images
workflow. If package storage ever runs short, the test-stack push is
the first thing to remove.

## The two sites

* **test.idptools.com** is deployed from `develop`, by
  `website-deploy-test.yml`, after a Selenium Tests run on `develop`
  succeeds. Its live suite then runs against it.
* **idptools.com** is deployed from `master` on every push, by
  `website-deploy.yml`, and its live suite runs after the deploy.

Both live suites also run on a nightly schedule. See
[Testing against the deployed sites](live-site-testing.md).

## Cutting a release

1. On `develop`, set `VERSION` to the new `M.N.P` and run
   `node client/version.js --sync-manifests`. Commit both.
2. Wait for `develop` to be green: Selenium Tests on the commit, the
   test.idptools.com deploy it triggers, and that site's live suite.
3. Open a pull request from `develop` to `master` and merge it.
4. Check the `master` runs: Docker Image CI (images, the two git tags,
   `release-M.N.P`), the idptools.com deploy and its live suite, and
   Selenium Tests on `master`.
5. Merge `master` back into `develop`, so the release's merge commit is
   in `develop`'s history.

Release 0.9.3 went through exactly these steps on 2026-11-14:
`ab732c52`, images `0.9.3.20261114082841`,
[Release 0.9.3](https://github.com/rcbj/id-proto-debugger/releases/tag/release-0.9.3).
