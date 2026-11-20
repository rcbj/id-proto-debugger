# Running the debugger

The published images, the TLS certificate, docker compose and docker run, building the images, and the debugger embedded in IYA STS.

## Running the published images

The api, the client and the embedded build are published on every build of
`master`, to the GitHub Container Registry and to Docker Hub, so they can be
run without building anything. Both registries get the same images with the
same tags from the same build — use whichever you prefer:

| GitHub Container Registry | Docker Hub |
|---|---|
| `ghcr.io/rcbj/id-proto-debugger-api` | `iyasec/id-proto-debugger-api` |
| `ghcr.io/rcbj/id-proto-debugger-client` | `iyasec/id-proto-debugger-client` |
| `ghcr.io/rcbj/id-proto-debugger-embedded` | `iyasec/id-proto-debugger-embedded` |

Tags: `latest` (the newest `master` build) and one `M.N.P.B` per build.
`develop` and pull requests build the images and publish nothing; the old
`develop` tag stopped moving on 2026-10-02. The embedded image is the
debugger built for IYA STS to serve, and is not run by itself.

`M.N.P.B` (for example `0.9.3.20261114082841`) is the build's version: `M.N.P`
is the `VERSION` file and `B` the build instant. The git tag of the same name
marks the commit that image was built from, so `git checkout
0.9.3.20261114082841` is the source of
`ghcr.io/rcbj/id-proto-debugger-api:0.9.3.20261114082841`. The first `master`
build of each `M.N.P` also creates the GitHub release `release-M.N.P`, whose
notes list every image with its digest. The version is also in each running
client's footer and in `/version.json`. See
[Releases, versions and images](releases.md).

No login is needed: the packages are public, so an anonymous `docker pull`
works.

### Pulling the images

```bash
# The newest master build
docker pull ghcr.io/rcbj/id-proto-debugger-api:latest
docker pull ghcr.io/rcbj/id-proto-debugger-client:latest

# Or one specific build, pinned to the commit tagged with the same version
docker pull ghcr.io/rcbj/id-proto-debugger-api:0.9.3.20261114082841
docker pull ghcr.io/rcbj/id-proto-debugger-client:0.9.3.20261114082841

# The same images from Docker Hub
docker pull iyasec/id-proto-debugger-api:latest
docker pull iyasec/id-proto-debugger-client:latest
```

The tags are listed at
<https://github.com/rcbj/id-proto-debugger/pkgs/container/id-proto-debugger-api>
(and `.../id-proto-debugger-client`) and at
<https://hub.docker.com/r/iyasec/id-proto-debugger-api> (and
`.../id-proto-debugger-client`).

### The TLS certificate

Both services serve TLS and need the certificate pair `./generate-tls-cert.sh`
writes, so that script is still run once, from a checkout. It needs Node.js
and npm on the host (it installs the client's dependencies to issue the
certificate with this project's own X.509 code) and `openssl`:

```bash
git clone https://github.com/rcbj/id-proto-debugger.git
cd id-proto-debugger
./generate-tls-cert.sh          # writes ./generated-tls; trust the root it prints
```

The script prints the root CA's fingerprint and writes it to
`./generated-tls-ca/stack-tls-root.pem`. Trust that root in your browser (or
accept the certificate on BOTH `https://localhost:3000` and
`https://localhost:4000` — the api is a separate origin, and a browser that has
not accepted it reports every call to it as a CORS error).

### With docker compose

Save this as `docker-compose.yml` beside the `generated-tls` directory the
script wrote:

```yaml
# id-proto-debugger from its published images on ghcr.io.
# DEBUGGER_TAG selects the build: latest (default) or an M.N.P.B version
# such as 0.9.3.20261114082841.
services:
  api:
    image: ghcr.io/rcbj/id-proto-debugger-api:${DEBUGGER_TAG:-latest}
    container_name: api
    environment:
      - CONFIG_FILE=./env/local.js
      - TLS_ENABLED=true
      - TLS_CERT_FILE=/etc/idptools/tls/stack-tls-cert.pem
      - TLS_KEY_FILE=/etc/idptools/tls/stack-tls-key.pem
    volumes:
      - ./generated-tls:/etc/idptools/tls:ro
    ports:
      - "4000:4000"
    restart: unless-stopped

  client:
    image: ghcr.io/rcbj/id-proto-debugger-client:${DEBUGGER_TAG:-latest}
    container_name: client
    environment:
      - CONFIG_FILE=./env/local.js
      - TLS_ENABLED=true
      - TLS_CERT_FILE=/etc/idptools/tls/stack-tls-cert.pem
      - TLS_KEY_FILE=/etc/idptools/tls/stack-tls-key.pem
    volumes:
      - ./generated-tls:/etc/idptools/tls:ro
    ports:
      - "3000:3000"
    depends_on:
      - api
    restart: unless-stopped
```

Then:

```bash
docker compose pull                                  # fetch the images
docker compose up -d                                 # start both services
DEBUGGER_TAG=0.9.3.20261114082841 docker compose up -d # or pin one build
docker compose logs -f                               # follow the logs
docker compose down                                  # stop and remove them
```

To take the images from Docker Hub instead, replace `ghcr.io/rcbj/` with
`iyasec/` in the two `image:` lines.

This is not the repository's own `docker-compose.yml`, which BUILDS the images
from source and also starts the mock STS used by the test suite.

### With docker run

The same two services without compose:

```bash
for svc in api:4000 client:3000; do
  docker run -d --name "${svc%%:*}" -p "${svc##*:}:${svc##*:}" \
    -e CONFIG_FILE=./env/local.js -e TLS_ENABLED=true \
    -e TLS_CERT_FILE=/etc/idptools/tls/stack-tls-cert.pem \
    -e TLS_KEY_FILE=/etc/idptools/tls/stack-tls-key.pem \
    -v "$PWD/generated-tls:/etc/idptools/tls:ro" \
    "ghcr.io/rcbj/id-proto-debugger-${svc%%:*}:latest"
done
```

Either way, open `https://localhost:3000`. The images are built with the
`local` configuration, which is what makes the client call the api at
`https://localhost:4000` — so the published images run on the machine whose
browser uses them, and register `https://localhost:3000/callback` as the
redirect URI with your identity provider.

## Building the docker image
```bash
yum install git
git clone --recurse-submodules https://github.com/rcbj/id-proto-debugger.git
yum install docker
systemctl start docker
cd id-proto-debugger
sudo docker build -t rcbj/debugger-client --build-arg CONFIG_FILE=./env/local.js -f client/Dockerfile .
sudo docker run -p 3000:3000 -e CONFIG_FILE=./env/local.js -d rcbj/debugger-client
sudo docker build -t rcbj/debugger-api --build-arg CONFIG_FILE=./env/local.js -f api/Dockerfile .
sudo docker run -p 4000:4000 -e CONFIG_FILE=./env/local.js -d rcbj/debugger-api
```
On other systems, the commands needed to start the debugger in a local docker container will be similar. The API container has to be able to establish connections to a remote IdP endpoint (whether locally in other docker containers, on the host VM, or over the network/internet).  On the test system, it was necessary to add "--net=host" to the "docker run" args. The network connectivity details for docker may vary from platform-to-platform.

## Embedded in the mock STS

The debugger has a third deployment shape besides the containers above and the
static idptools.com build: **embedded inside the
[mock STS](https://github.com/rcbj/iya-sts)**, which serves the UI from a
listener of its own behind an OIDC sign-in and runs the api as a child process
on a unix socket behind its own proxy. This repository builds the tree that
service consumes:

```bash
git submodule update --init
embedded/build.sh --out /path/to/tree          # without docker
docker build -f embedded/Dockerfile -t rcbj/id-proto-debugger-embedded:dev \
  --build-context ubuntu=docker-image://ghcr.io/rcbj/id-proto-debugger/mirror/ubuntu:latest \
  --build-arg GIT_COMMIT=$(git rev-parse --short=12 HEAD) .
```

The `--build-context` takes `ubuntu:latest` from this repository's private
image mirror rather than Docker Hub, as every build here does; it needs
`docker login ghcr.io`, and dropping it builds from Docker Hub instead.

Nothing about the standalone debugger changes. The contract — the tree, the
`DEBUGGER_*` environment the api child reads, and the address allow-list it
enforces — is in `embedded/CLAUDE.md`.
