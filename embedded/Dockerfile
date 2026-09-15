# embedded/Dockerfile — the debugger tree the mock STS embeds, as an image.
#
#   docker build -f embedded/Dockerfile -t rcbj/id-proto-debugger-embedded:<tag> .
#
# Build context: the REPOSITORY ROOT. The final image is FROM scratch and holds
# nothing but the tree embedded/CLAUDE.md describes:
#
#   /debugger/ui  /debugger/api  /debugger/common  /debugger/version.json
#
# It is not meant to be RUN — it has no shell, no node and no CMD. It exists to
# be copied from: the mock STS's own Dockerfile does
# `COPY --from=rcbj/id-proto-debugger-embedded:<tag> /debugger/ <dest>`, which
# the classic builder supports for an image by name. That keeps the mock STS's
# image build free of this repository's toolchain (browserify, terser, the
# api's npm install) while the tree it gets is byte-for-byte what
# embedded/build.sh writes — because the build stage below RUNS build.sh rather
# than restating it. One description of the tree, not two.
#
# CLASSIC BUILDER ONLY, deliberately: the machines this is built on have no
# BuildKit, so there is no `# syntax` line, no `RUN --mount` and no
# `--build-context` here. Node is installed the way api/Dockerfile and
# client/Dockerfile install it (nvm, NODE_VERSION pinned), so the api's
# node_modules are resolved by the same node the other images run.

FROM ubuntu:latest AS build

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# ONE RUN, for the reason api/Dockerfile gives above its own: a cached
# `apt-get update` layer names package versions the archive has dropped.
RUN apt-get update \
    && apt-get -y install curl \
        ca-certificates \
        tar

ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash
RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default
# The same symlink api/Dockerfile makes, so `node` and `npm` are on PATH
# whatever directory nvm actually chose.
RUN source $NVM_DIR/nvm.sh \
    && ln -sf "$(dirname "$(nvm which default)")"/* /usr/local/bin/
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH
RUN node -v && npm -v

WORKDIR /usr/src/build
# Only what build.sh reads. .dockerignore already keeps node_modules,
# client/dist and .git out of the context, and build.sh excludes them again
# for a checkout that has them.
COPY VERSION ./VERSION
COPY client/ ./client/
COPY api/ ./api/
COPY common/ ./common/
COPY embedded/build.sh ./embedded/build.sh

# The build number is fixed HERE, once, so the tree reports the same M.N.O for
# as long as the image exists. GIT_COMMIT has to be passed: the context has no
# .git to ask.
ARG BUILD_NUMBER
ARG GIT_COMMIT
RUN chmod +x embedded/build.sh \
    && BUILD_NUMBER="${BUILD_NUMBER}" GIT_COMMIT="${GIT_COMMIT}" \
       embedded/build.sh --out /debugger \
    && cat /debugger/version.json

FROM scratch
COPY --from=build /debugger/ui /debugger/ui
COPY --from=build /debugger/api /debugger/api
COPY --from=build /debugger/common /debugger/common
COPY --from=build /debugger/version.json /debugger/version.json
