# Code Coverage

Code coverage for this project spans two domains that the Selenium suite
exercises out-of-process:

1. **Frontend (browser)** — the browserified bundles (`oauth2_oidc_1.js`,
   `oauth2_oidc_2.js`, `introspection.js`, …) running in Selenium-driven Chrome.
2. **Backend (Node)** — the Express API (`api/server.js`, `common/data.js`).

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
the reports. Equivalent manual steps:

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

## Output

- `./coverage/frontend/report/index.html` — frontend/browser coverage
- `./coverage/api/index.html` — API/Node coverage
- `./coverage/frontend/.nyc_output/*.json` — raw frontend Istanbul data
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
- **Unified report:** frontend (Istanbul) and backend (c8/V8) are reported
  separately to avoid source-path collisions between the two containers (both use
  `/usr/src/app`). To merge them into one report, point
  [`monocart-coverage-reports`](https://github.com/cenfun/monocart-coverage-reports)
  at both `./coverage/frontend/.nyc_output` (Istanbul) and the API's raw V8
  output.
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
