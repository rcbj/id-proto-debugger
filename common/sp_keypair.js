// File: sp_keypair.js
//
// ---------------------------------------------------------------------------
// The SAML SP key pair the SAML tests sign and decrypt with.
//
// It is NOT stored in this repository. common/common.sh generateSpKeyPair()
// creates a fresh one at the start of every run and exports it:
//
//   SAML_SP_PRIVATE_KEY  the private key, PEM
//   SAML_SP_CERT         the matching self-signed certificate, PEM
//
// The certificate is registered on the Keycloak SAML client in the same run
// (SAML_SP_SIGNING_CERT), so the request signatures the tests produce validate
// against it. The pair therefore has to come from that one place: a test that
// generated its own would sign with a key Keycloak has never seen.
//
// Run the tests through ./local-run-tests.sh, ./docker-run-tests.sh or
// ./remote-run-tests.sh and this is set for you. Running a single test script by
// hand needs the two variables in the environment — export them from a run of
// generateSpKeyPair, or the script says so and stops.
// ---------------------------------------------------------------------------

function readSpKeyPair() {
  const privateKey = process.env.SAML_SP_PRIVATE_KEY;
  const certificate = process.env.SAML_SP_CERT;
  if (!privateKey || !certificate) {
    throw new Error(
      "SAML_SP_PRIVATE_KEY and SAML_SP_CERT are not set. The SP key pair is generated per run " +
      "(common/common.sh generateSpKeyPair) rather than kept in the repository, and its certificate " +
      "is what Keycloak validates the request signature against — so run this through " +
      "./local-run-tests.sh, ./docker-run-tests.sh or ./remote-run-tests.sh, or export the two " +
      "variables yourself.");
  }
  if (privateKey.indexOf("PRIVATE KEY") < 0) {
    throw new Error("SAML_SP_PRIVATE_KEY does not look like a PEM private key.");
  }
  if (certificate.indexOf("CERTIFICATE") < 0) {
    throw new Error("SAML_SP_CERT does not look like a PEM certificate.");
  }
  return { privateKey: privateKey, certificate: certificate };
}

module.exports = { readSpKeyPair: readSpKeyPair };
