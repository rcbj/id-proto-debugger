# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# THE GORDIAN ENVELOPE WITNESS, AS AN IMAGE (#480).
#
# bc-envelope-cli is Blockchain Commons' own command-line tool over the Rust
# crates that define Gordian Envelope (bc-envelope, dcbor, bc-components).
# The JavaScript port is a prerelease, so this is the released
# implementation the debugger's pure-JS engine (client/src/
# gordian_envelope.js) is held to: tests/gordian_envelope_engine.js has it
# verify our signatures and digests, and verifies, elides and reads what it
# signs.
#
# Built with cargo from crates.io at the pinned version (--locked uses the
# crate's own Cargo.lock), and pushed to the private mirror as
# gordian-witness:<version> by .github/scripts/mirror-builds.sh
# (.github/image-mirror-builds.txt); tests/Dockerfile copies the one binary
# out of it, so no test-image build reaches crates.io. It links only libc,
# libm and libgcc_s, which the tests image (ubuntu) has.
#
# A bump changes the version below, the tag in image-mirror-builds.txt, the
# FROM in tests/Dockerfile and the TAG in tests/gordian_witness.js.
FROM rust:1.97-bookworm AS build
RUN cargo install --locked --root /opt/envelope bc-envelope-cli@0.35.0 \
 && /opt/envelope/bin/envelope --version

FROM scratch
COPY --from=build /opt/envelope/bin/envelope /envelope/envelope
