var config = {
  apiUrl: "http://localhost:4000",
  uiUrl: "http://localhost:3000",
  hostname: "0.0.0.0",
  port: "4000",
  logLevel: "debug",
  // SAML Service Provider identity (this debugger acting as an SP).
  spEntityId: "http://localhost:3000/saml/sp",
  acsUrl: "http://localhost:4000/samlacs",
  sloUrl: "http://localhost:4000/samlslo",
  // SSRF guard (api/ssrf_guard.js). OFF here, and this is the exception that
  // proves the rule: the whole point of the local stack is that the api talks to
  // Keycloak on localhost:8080 and the mock STS on localhost:8081. With the guard
  // on, every token, introspection and WS-Trust call this service makes would be
  // refused. Deployed configurations leave it ON.
  blockPrivateNetworkCalls: false,
  // Outbound destinations this service refuses to call, as RANGES — a CIDR block
  // ("10.0.0.0/8") or a first-last pair ("10.0.0.0-10.255.255.255"). A bare single
  // address is refused with a logged reason: a network policy written one host at
  // a time almost always means the block that host sits in. Replacing this list
  // replaces the policy wholesale; omit it (or leave it empty) to use the defaults
  // baked into ssrf_guard.js, which are these.
  blockedAddressRanges: [
    "127.0.0.0/8",        // loopback
    "0.0.0.0/8",          // "this host on this network"
    "10.0.0.0/8",         // RFC 1918 private
    "172.16.0.0/12",      // RFC 1918 private
    "192.168.0.0/16",     // RFC 1918 private
    "169.254.0.0/16",     // link-local, including 169.254.169.254 (cloud metadata)
    "100.64.0.0/10",      // RFC 6598 carrier-grade NAT
    "192.0.0.0/24",       // IETF protocol assignments
    "198.18.0.0/15",      // benchmarking
    "::1/128",            // IPv6 loopback
    "fe80::/10",          // IPv6 link-local
    "fc00::/7"            // IPv6 unique local
  ]
};

module.exports = config;
