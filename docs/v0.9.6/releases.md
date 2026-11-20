# Releases, versions and images

What each release changed is [Release notes](release-notes.md).

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

## Stamping, tagging and where the version shows

Builds are numbered **M.N.P.B** — a three-part release and a build number:

| Part | Meaning | Source |
|---|---|---|
| **M** | major | the repo-root [`VERSION`](../../VERSION) file |
| **N** | minor | the repo-root [`VERSION`](../../VERSION) file |
| **P** | patch | the repo-root [`VERSION`](../../VERSION) file |
| **B** | build number | generated per build — the UTC build instant as `YYYYMMDDHHMMSS` |

So a build of the current `0.9.0` release looks like **`0.9.0.20260726143205`**. (Until 2026-11-13 `VERSION` held two parts and builds were `M.N.B`, such as `0.9.20260726143205`; those tags remain.) The build number is a timestamp rather than a counter so that it is unique for every build without any shared state, always increases, and says when the artifact was produced. Set `BUILD_NUMBER` to override it (for example with a CI run number); if you do, keeping it unique and increasing is up to you.

Each project's `package.json` (`api`, `client`, `tests`) carries the release, `M.N.P`, exactly — a valid semver as it stands. The build number lives only in `version.json`, because `M.N.P.B` is not a semver.

To cut a new release, edit `VERSION` (for example `0.9.0` to `0.9.1`), then run `node client/version.js --sync-manifests` to bring the three manifests along. `node client/version.js --check-manifests` reports drift (non-zero exit), and the static build warns about it.

**Where it comes from.** The build number is fixed when an artifact is *built*, not when it runs, so every page of a deployment reports the same build and restarting a container does not invent a new one:

* the container image runs `node client/version.js --stamp public` during `docker build`, and `server.js` reads that record once at startup (pass `--build-arg BUILD_NUMBER=… --build-arg GIT_COMMIT=…` to supply CI values);
* the static build (`npm run build`) stamps `dist/version.json` at the start of the build.

**Tagging.** The three build workflows — *Docker Image CI*, *Deploy Static Site (idptools.com)*, and *Deploy Static Site (test.idptools.com)* — log the version they are building (in the job log and the run summary), pass its build number into the build so the artifact and the tag agree, and then tag the built commit twice:

| Tag | Example | Behaviour |
|---|---|---|
| `M.N.P.B` | `0.9.0.20260726143205` | created once, never moved — the permanent record of one build |
| `M.N.P` | `0.9.0` | **force-moved** to the newest build of that release on every build |

The floating `M.N.P` tag (it was `M.N` — `0.9` — before 2026-11-13, and that tag no longer moves) is the usual moving-tag pattern (as `actions/checkout@v4` does), so anyone who has fetched it needs `git fetch --tags --force` to follow it. Docker Image CI tags only on pushes and manual runs, never on pull requests.

**Releases.** The first `master` build of each `M.N.P` also tags that commit `release-M.N.P`, which is never moved, and creates the GitHub release *Release M.N.P*, marked Latest. Its notes list every published image with its digest and the pull requests merged since the previous `release-*` tag. Later builds of the same line leave it alone. `release-0.9.3` was the first made this way; the series before it was made by hand. See [Releases, versions and images](releases.md).

**Where it shows.** The footer of every page carries `v M.N.P.B`; hovering it reveals the build number, the build time, and the commit it was built from. The same record is served as machine-readable JSON at **`/version.json`** on both deployment styles:

```json
{ "version": "0.9.0.20260726143205", "release": "0.9.0", "major": "0",
  "minor": "9", "patch": "0", "build": "20260726143205",
  "commit": "228a63c63edd", "builtAt": "2026-07-26T14:32:05Z" }
```

## What a build of `master` publishes

Every push to `master` runs Docker Image CI, which builds the api, the
client and the embedded debugger and then, from `master` only:

* **Images**, public, with the same tags on both registries:

  | GitHub Container Registry | Docker Hub |
  |---|---|
  | `ghcr.io/rcbj/id-proto-debugger-api` | `iyasec/id-proto-debugger-api` |
  | `ghcr.io/rcbj/id-proto-debugger-client` | `iyasec/id-proto-debugger-client` |
  | `ghcr.io/rcbj/id-proto-debugger-embedded` | `iyasec/id-proto-debugger-embedded` |

  Each is tagged `M.N.P.B`, `latest` and `M.N.P`. `M.N.P` is the tag a
  consumer pins: IYA STS's Dockerfile names
  `id-proto-debugger-embedded:<M.N.P>`. Builds before 2026-11-20 pushed no
  `M.N.P`; `gh workflow run dockerimage.yml --ref develop -f
  retag=<M.N.P.B>` gives a published release build that tag on both
  registries, and moves the git tag `M.N.P` to its release commit,
  without building anything. The embedded image is
  `FROM scratch` and holds only the built tree that IYA STS's own image
  copies in; it is not run by itself.
* **Git tags.** `M.N.P.B` on the commit, created once and never moved,
  whose message names the images. `M.N.P`, force-moved by each `master`
  build of that line, so it names the released commit (a develop build
  moved it too until 2026-11-20).
* **A GitHub release**, on the first `master` build of a line only:
  the tag `release-M.N.P` is created on that commit and never moved, and
  the release is titled "Release M.N.P" and marked Latest. Its notes
  list every published image with its digest, the commit, and every
  individual change since the previous `release-*` tag, one line each:
  GitHub's generated list of merged pull requests, then each commit that
  no feature pull request carried, under "Committed without a pull
  request" (`.github/scripts/release-changes.sh`). GitHub's list alone
  sees only pull requests, so a release whose work was committed straight
  onto `develop` — 0.9.4 — showed nothing but its own promotion PR and a
  compare link. A later build of the same line finds the release and leaves it
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

### A release candidate

To rehearse a release without making one, dispatch Docker Image CI on
`develop` with **candidate** checked:

```bash
gh workflow run dockerimage.yml --ref develop -f candidate=true
```

It runs the `master` path with three differences:

* the images go to both registries tagged `M.N.P.B` and
  `M.N.P-candidate`, and `latest` is not moved;
* the git tag is `release-M.N.P-candidate`, force-moved by each candidate
  build (the `M.N.P.B` and floating `M.N.P` tags are made as on any
  build);
* **no GitHub release is created**, because a release is permanent. The
  notes it would carry are written to the run's summary instead.

The candidate input is ignored on `master`. The real release later finds
no `release-M.N.P` tag and makes it as usual; the previous release is
still found among the plain `release-*` tags, which a `-candidate` tag
is not one of. Deploy the candidate to test.idptools.com with
`gh workflow run website-deploy-test.yml --ref develop`, and run its live
suite after it.

Release 0.9.3 went through exactly these steps on 2026-11-14:
`ab732c52`, images `0.9.3.20261114082841`,
[Release 0.9.3](https://github.com/rcbj/id-proto-debugger/releases/tag/release-0.9.3).
