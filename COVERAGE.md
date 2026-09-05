# Code Coverage

Code coverage for this project spans three domains:

1. **Frontend (browser)** — the browserified bundles (`oauth2_oidc_1.js`,
   `oauth2_oidc_2.js`, `introspection.js`, …) running in Selenium-driven Chrome.
2. **Backend (Node)** — the Express API (`api/server.js`, `common/data.js`).
3. **In-process (Node)** — the modules the test scripts load and drive
   *themselves*, inside the tests container. About thirty jobs here never open a
   browser at all: they take the real `client/src` and `api` modules through
   `module_paths.requireSharedModule()` and run them against the RFCs' own
   vectors. The first two domains cannot see any of it.

**Why the third one exists.** Until 2026-08-23 there were two, and the number
that produced did not merely understate the suite — it pointed at the wrong
work. `api/krb5_frame.js` read 29.7% branch coverage with every one of its
malformed-frame rejections flagged uncovered, while `tests/api_krb5_relay.js`
asserts each of them by name; `client/src/scim_client.js` read 40.3% with
`chooseDigestChallenge`, `verifyAuthenticationInfo` and `hobaToBeSigned` all
flagged, while `tests/scim_engine.js` calls all three. On that report **336 of
the api's 474 own-code missing branches, and roughly 2,935 of the frontend's
10,092, sat in modules that already had a node test.** Anyone writing tests
against it would have written the ones that already existed.

Coverage is **opt-in**. The default build and the normal test runs
(`docker-run-tests.sh`, `local-run-tests.sh`) are completely unaffected; nothing
is instrumented unless you explicitly enable it.

## How it works

### Frontend — Istanbul + a coverage beacon
- When the client image is built with `--build-arg COVERAGE=true`, the bundles
  are re-built with **`babel-plugin-istanbul`** instrumentation (via a `babelify`
  browserify transform), and `client/src/coverage_beacon.js` is appended to each
  bundle.
- In the browser, Istanbul accumulates coverage in `window.__coverage__`. Because
  that object is reset on every full page load (and this app hops between
  `oauth2_oidc_1.html`, `oauth2_oidc_2.html`, `introspection.html`, …), the beacon ships
  it to the client server **asynchronously on a short interval** (and on
  `visibilitychange`) while the page is alive. Shipping at page-dismissal time
  does not work: Chrome drops synchronous `XMLHttpRequest` fired during
  dismissal, and `navigator.sendBeacon`/`fetch(keepalive)` reject payloads over
  ~64 KB, which coverage routinely exceeds. Repeated snapshots are harmless — the
  server writes each as its own file and `nyc` merges them.
- The client server, when started with `COVERAGE=true`, exposes `POST /coverage`
  and writes each payload as an Istanbul coverage file under
  `COVERAGE_DIR` (default `/coverage/frontend/.nyc_output`).
- `nyc report` later renders those files. It runs **inside the client image** so
  the source paths Istanbul recorded (`/usr/src/app/src/*.js`) resolve.

### In-process — `NODE_V8_COVERAGE` + c8
- `tests/run-report.js` sets **`NODE_V8_COVERAGE`** on every job it spawns when
  `COVERAGE=true`. That is node's own mechanism: the child writes raw V8
  coverage into the named directory as it exits, with no wrapper binary in the
  spawn path and nothing for a test to opt into.
- It is set for **every** job, not only the browserless ones. A page test that
  also loads a shared module in-process contributes what it ran there —
  `tests/pki_page.js` does exactly that with `client/src/x509.js`.
- At the end of the run, `run-report.js` renders the pile with **c8** into
  `/coverage/node`. It runs **inside the tests container**, for the same reason
  `nyc report` runs inside the client image: the raw data names the paths the
  modules were loaded from, and only that filesystem still has them.
- The test scripts themselves are excluded — every job's `script`, plus the
  helpers (`module_paths.js`, `wait_for.js`, `random_username.js`). The tests
  image copies the shared modules **flat** beside the test scripts, so there is
  no directory to separate them by, only the name; excluding by name is safe
  because `tests/jwk_pem_encoding.js` already asserts that no shared module
  collides with a test script in that flat copy.
- `--allowExternal` is passed, and is not decorative: c8 drops every file
  outside its cwd by default, and on a **host** run the modules under test live
  in `../client/src` and `../api`.
- The temp directory is emptied at the start of each run. `NODE_V8_COVERAGE`
  appends a file per process, so a leftover pile would be merged into the next
  run's numbers — a report that improves every time it is rendered and never
  says why.

### Backend — c8
- The API image, built with `COVERAGE=true`, installs **c8**.
- The coverage compose override launches the API as
  `c8 … node server.js`. `server.js` (under `COVERAGE=true`) installs a
  `SIGTERM`/`SIGINT` handler that exits cleanly so c8 can flush V8 coverage when
  the container stops.
- c8 writes an HTML/lcov report to `/coverage/api`.

## Running it

```bash
./run-coverage.sh
```

That script runs the full suite with both compose files
(`docker-compose-run-tests.yml` + `docker-compose-coverage.yml`), then renders
the reports. The **in-process** report needs no step of its own — the suite
renders it itself before the tests container exits. Equivalent manual steps:

```bash
CONFIG_FILE=./env/docker-tests.js \
  docker compose -f docker-compose-run-tests.yml -f docker-compose-coverage.yml \
  up --build --abort-on-container-exit --exit-code-from tests

# Render the frontend report from the collected data (client image has the source):
CONFIG_FILE=./env/docker-tests.js \
  docker compose -f docker-compose-run-tests.yml -f docker-compose-coverage.yml \
  run --rm --no-deps client \
  npx nyc report --temp-dir /coverage/frontend/.nyc_output \
                 --report-dir /coverage/frontend/report \
                 --reporter=html --reporter=lcov --reporter=text-summary

docker compose -f docker-compose-run-tests.yml -f docker-compose-coverage.yml down
```

## The fourth report, which is the one to read

The three above do not reconcile, and until 2026-09-01 nothing tried to. That
was fine for a total and useless for a **work list**: ranking the files by what
any one report calls uncovered points at the wrong work — the same failure this
document describes for the third domain, fixed there for the TOTAL and never for
the FILE LIST.

`tests/coverage_merge.js` merges the three into one number and one ranked list.
`./run-coverage.sh` runs it at the end, on the HOST — the three `lcov.info`
files are on the bind mount by then and the containers that could read them have
been torn down. It takes no dependency (a checkout need not have installed
`tests/node_modules` to have run the launcher) and can be run on its own against
an existing `./coverage`:

```bash
node tests/coverage_merge.js            # merge and rank
node tests/coverage_merge.js --top 40
node tests/coverage_merge.js --check    # the ratchet
node tests/coverage_merge.js --write-floors
```

**What it changes, measured on the 2026-08-29 run.** `common/xmldsig.js` was
the **#1 entry of the frontend report** (594 uncovered lines, 45.4%) *and* the
**#1 entry of the api report** (1,475, 33.7%) — and is **86.8%** covered once
the three are merged. So is `client/src/krb5_pac.js` (45.2% → 86.8%), and
`client/src/x509.js` is 58.9% → 90.4%. Anyone writing tests off the top of
either list would have written tests that already existed. The union came to
**83.9%** against the 70.4 / 66.6 / 80.2 the three reports published — most of
that from the merge, the rest from the exclusions above.

**It resolves paths rather than basenames, and that is not fussiness.** The
obvious merge — key on the file name — is wrong here invisibly: `api/server.js`
and `api/node-ldapjs/lib/server.js` are both `server.js`, so a basename merge
adds 685 lines of a vendored library's uncovered code to the api's own row under
a name that is not theirs. 47 basenames in the three reports resolve to more
than one path. Two rules do the resolving and both were written against real
failures found while writing it:

* **A path git TRACKS beats one it does not.** Several modules exist twice in a
  working tree because a Docker build cannot COPY from outside its context and
  the build stages them — `common/xmldsig.js` becomes `api/xmldsig.js` and
  `client/src/xmldsig.js`, `common/data.js` likewise — and the reports name the
  staged copies, because that is what the container had. Resolving to one of
  those splits a module's coverage across two rows and understates both.
* **A path inside a SUBMODULE is believed.** git tracks a submodule as one
  entry and not as its contents, so `api/node-ldapjs/lib/server.js` is
  "untracked" like any staged copy — and the rule above, applied alone,
  resolved it to `api/server.js`. That is the exact failure the resolver exists
  to prevent, arriving through the rule written to prevent it.

Anything it cannot place is counted under an `(unresolved)` name and **warned
about** rather than dropped: a merge that quietly loses a file is a coverage
number that improves for no reason, which is the one direction it must never
move by itself.

## The ratchet

Nothing read any of these numbers before. `.github/workflows/tests.yml` uploads
`./coverage` as an artifact and stops, so coverage could fall ten points between
two green runs and nothing would say so.

`tests/coverage_floors.json` holds a floor per domain and one for the union.
`./run-coverage.sh` runs `--check` after the reports are rendered and **fails
the run** on a drop — but only when the tests themselves passed, because a
coverage regression reported in place of a red test is a report about the wrong
thing.

Each floor is what a run achieved **less one point**, and the margin is spent
when the floor is WRITTEN rather than when it is checked. A merged number is not
exactly reproducible — a job skipped for want of a service takes its lines with
it, and the pool decides which process records a module first — so a floor set
at exactly what one run achieved is a coin toss for the next. Forgiving a drop
at check time would have put the same slack somewhere nobody reading that file
can see it; here the number in the file is the number that must be met.

`--write-floors` is how they move, deliberately, in a commit somebody reviewed.
Nothing raises them automatically: one lucky run would become a threshold nobody
chose, and the next honest run would be red for it. **Never lower one without
saying in the commit message what stopped being tested.**

## Output

- `./coverage/merged/summary.json` — the merged totals and the ranked file list
- `./coverage/merged/lcov.info` — the union, with repo-relative paths, so
  anything that reads an lcov (genhtml, a coverage service, an editor's gutter)
  can render it
- `./coverage/frontend/report/index.html` — frontend/browser coverage
- `./coverage/api/index.html` — API/Node coverage
- `./coverage/node/index.html` — in-process/Node coverage
- `./coverage/frontend/.nyc_output/*.json` — raw frontend Istanbul data
- `./coverage/node/tmp/*.json` — raw in-process V8 data
- `./coverage/` is gitignored.

## Notes / limitations

- **Last-page coverage:** coverage is shipped on a ~1s interval while a page is
  alive, so whatever has accrued since the last tick on the final page (before
  `driver.quit()`) may not be captured. These tests navigate between pages
  frequently, so the bulk is collected; if you need the final page complete,
  navigate to `about:blank` before quitting.
- **c8 flush on stop:** the API report depends on the container stopping
  gracefully (`SIGTERM` → clean exit). `stop_grace_period` is set to 30s. If
  `./coverage/api` is empty, increase the grace period or stop the API container
  explicitly before tearing down.
- **The same module can appear in two reports, at two paths.** A shared module
  driven both ways — `client/src/scim_client.js` runs in the browser *and* in
  `tests/scim_engine.js` — is recorded by the frontend build as
  `/usr/src/app/src/scim_client.js` and by the in-process run as
  `/usr/src/app/scim_client.js`, because the tests image copies it flat. The two
  do not merge **in the three rendered reports**, and neither number alone is
  the module's real coverage. The fourth report below reconciles them; the flat
  copy is what makes the tests image work at all, so it is not going away.
- **A job that is killed writes nothing.** `NODE_V8_COVERAGE` is flushed by
  node on exit, `process.exit()` included, but not on `SIGKILL`. A test the
  runner or compose kills contributes no in-process coverage; it still appears
  in `report.html` as a failure, which is the louder signal anyway.
- **Vendored and generated code is out of the denominator, in two places.**
  `api/node-ldapjs` is a fork of ldapjs used UNMODIFIED, pinned at upstream's
  final commit because upstream is decommissioned; `client/version.js`, which
  `api/Dockerfile` stages into the api image, is a build script. Both are
  excluded at COLLECTION time by the api's `c8` invocation
  (`docker-compose-coverage.yml`) and again by the merge below, so the two
  numbers agree. The in-process domain already excluded them
  (`coverageExcludes()` in `tests/run-report.js`). Excluding node-ldapjs alone
  moved the api report from 66.6% to 69.8% with no test written, and removed
  what had been its **#2 and #4** entries.
- **Vendored libraries** (`jquery`, `dompurify`, …) are not instrumented:
  `babel-plugin-istanbul`/`babelify` skip `node_modules` by default.
- **A bundle missing from the coverage loop reports nothing, silently — and
  seven were.** The instrumented bundles are listed a THIRD time in
  `client/Dockerfile`'s `COVERAGE` block, separately from the `RUN browserify`
  lines above it and from `BUNDLES` in `client/build.js`. Missing from the first
  two is loud (a page whose `<script>` 404s fails its own suite); missing from
  the third is not — the page builds, ships, works and passes everything, and
  the only symptom is a number in this report. Until 2026-08-22 all six Kerberos
  bundles and `pki` were absent from it, and the Dockerfile had carried a
  comment *saying so* about six of them for months.

  They are all in it now, and `coverageListCoversEveryBundle()` in
  `tests/jwk_pem_encoding.js` compares the three lists on every **ordinary**
  suite run — not just under `./run-coverage.sh`, which is the point, since the
  plain launchers never execute that block and so cannot see a gap in it. It
  fails naming the bundle and which list it is missing from, and it also catches
  a `--standalone` name that disagrees between the two builds, because that
  global is what every inline `onclick` on the page calls: a mismatch makes
  every click on that page a `ReferenceError` under coverage and nowhere else.
