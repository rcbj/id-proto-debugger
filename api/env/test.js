var config = {
  apiUrl: "https://api.tools.test.idptools.io",
  uiUrl: "https://tools.test.idptools.io",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "info",
  // SAML Service Provider identity (this debugger acting as an SP).
  spEntityId: "https://tools.test.idptools.io/saml/sp",
  acsUrl: "https://api.tools.test.idptools.io/samlacs",
  sloUrl: "https://api.tools.test.idptools.io/samlslo",
  // SSRF guard (api/ssrf_guard.js). ON — a deployed api must not be usable as a
  // probe into the network it runs in. This is also the code default, so removing
  // the line changes nothing; it is written out to make the policy visible.
  blockPrivateNetworkCalls: true,
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
}

module.exports = config;
