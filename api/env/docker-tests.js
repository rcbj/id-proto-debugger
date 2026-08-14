var config = {
  apiUrl: "http://api:4000",
  uiUrl: "http://client:3000",
  hostname: "0.0.0.0",
  port: "4000",
  logLevel: "debug",
  // Timeout, in milliseconds, on every outbound axios call this service makes
  // (token, introspection, revocation, device-authorization and userinfo
  // endpoints, the SAML metadata and ArtifactResolve back-channels, the
  // WS-Trust STS, the DCR endpoint). A NUMBER, not a string. axios has no
  // default of its own, so without this a host that accepts the connection and
  // then never answers holds the request open for minutes. Omit it to use the
  // code default of 10000; a value that is not a positive number is logged and
  // ignored.
  callTimeout: 10000,
  // Budget for reaching a USABLE connection on those same calls — DNS, TCP
  // connect, and on https the TLS handshake — enforced on the agent by
  // api/connect_timeout.js. A NUMBER of milliseconds.
  //
  // It stops counting the moment the connection is up, which is what makes it a
  // different deadline from callTimeout rather than a smaller copy of one: a
  // dead or firewalled address fails inside connectionTimeout, while a host
  // that has answered still gets the whole callTimeout to produce a response.
  // Keep it BELOW callTimeout; omit it for the code default of 5000. A value
  // that is not a positive number is logged and ignored.
  connectionTimeout: 5000,
  // Largest response body, in BYTES, accepted from any of those outbound calls
  // (axios's maxContentLength). A NUMBER; 1048576 is 1 MiB.
  //
  // A timeout does not bound a response: a host that answers promptly and then
  // streams indefinitely is inside its deadline while this service buffers the
  // whole body in memory. axios's own default is -1, unlimited, so without this
  // the only ceiling is the heap. axios enforces it as the bytes arrive and
  // abandons the download once the cap is passed.
  //
  // Raise it if you need to proxy an unusually large document through
  // /samlmetadata — a federation METADATA AGGREGATE (eduGAIN, InCommon) is tens
  // of megabytes, though a single IdP's descriptor is far below this. A value
  // that is not a positive number is logged and ignored (0 would refuse every
  // response that has a body).
  maxContentLength: 1048576,
  // How many redirects an outbound call may follow (axios's maxRedirects). A
  // NUMBER; a whole number, and 0 is allowed.
  //
  // axios's own default is 21. A chain is unbounded work behind one URL — every
  // hop is a fresh lookup and connection — and a redirect is how a public host
  // sends this service somewhere private ("302 Location:
  // http://127.0.0.1:8080/"), which the SSRF guard refuses on the hop itself.
  //
  // 0 is legal and means follow none: axios then hands the 3xx back as the
  // response, and since a non-2xx is a failure to these endpoints, the caller
  // sees the upstream's status (302) with the endpoint's error body and no
  // Location. That suits a deployment that expects no redirects at all; it is
  // not a general "be careful" setting. A negative or fractional value is
  // logged and ignored, because axios would silently fall back to its own 21
  // rather than to anything intended here.
  maxRedirects: 5,
  // The User-Agent sent on every outbound call. `{{VERSION}}` is replaced with
  // the build version (M.N.O), the same placeholder the client's footer uses.
  //
  // Without this axios announces itself as "axios/<its version>", which tells
  // the operator of an identity provider nothing about who is calling — and
  // this service appears in other people's access logs by design. A value with
  // no placeholder in it is sent verbatim.
  userAgent: "Identity Protocol Debugger/{{VERSION}}",
  // Whether outbound connections are pooled and reused (the agents' keepAlive).
  // A BOOLEAN; only an explicit false turns it off, so a missing or misspelled
  // key stays on. A quoted "false" is refused and logged, since it is truthy.
  //
  // On, a debugger session that calls the token endpoint, then introspection,
  // then userinfo on the same host stops paying for a TCP connection and a TLS
  // handshake each time. It is also why the api's outbound agents are shared
  // rather than built per call: an agent holds the idle-socket pool, so a
  // per-call agent would pool nothing AND leak the socket it parked.
  keepAlive: true,
  // The ports the Kerberos relay (api/krb5_relay.js) may connect to.
  //
  // This setting exists because `POST /krb5/kdc` is a broader primitive than
  // anything else this service does: it carries CALLER-SUPPLIED BYTES to a
  // CALLER-SUPPLIED host and port over a raw TCP or UDP socket. An HTTP fetcher
  // aimed at port 22 gets nothing useful; a byte relay aimed at port 22 is a port
  // scanner whose payload the caller chooses. So the reachable ports are an
  // allowlist, not a denylist.
  //
  // 88 is Kerberos, 464 is kpasswd (password change) and 749 is kadmin. A
  // malformed entry is dropped with its reason logged; an allowlist that ends up
  // empty refuses every call, which is the safe direction but is almost certainly
  // a mistake. Omit the setting entirely to get these three.
  //
  // Note what this does NOT relax: the address policy above still applies, and so
  // does the requirement that the payload actually be an AS-REQ, a TGS-REQ or an
  // AP-REQ (api/krb5_frame.js). The relay also reuses `connectionTimeout`,
  // `callTimeout` and `maxContentLength` from this same file.
  krb5AllowedPorts: [88, 464, 749],
  // The ports POST /krb5/service may reach — the AP exchange, i.e. presenting a
  // ticket to a Kerberos-protected service.
  //
  // This is a BROADER capability than the KDC relay and is therefore OFF by default
  // (an absent or empty setting refuses every call). The reason it cannot be bounded
  // the same way: a Kerberos service can be on any port — 443 for HTTP, 1433 for SQL
  // Server, 389 for LDAP — so no small allowlist covers the real cases. What bounds
  // it instead is the payload check in api/krb5_frame.js, which requires a GSS
  // InitialContextToken naming the Kerberos v5 mechanism and wrapping a well-formed
  // AP-REQ (or a bare AP-REQ). An HTTP request, a Redis command and a TLS handshake
  // all fail that.
  //
  // Set it to a list of ports, or to the string "any" if a deployment genuinely needs
  // arbitrary ones. "any" is a word rather than an empty list or a 0 so that enabling
  // it is unmistakable rather than a plausible typo.
  // Here it is the mock STS's protected service (HTTP/web.example.com).
  krb5ServicePorts: [8888],
  // SAML Service Provider identity (this debugger acting as an SP).
  spEntityId: "http://client:3000/saml/sp",
  acsUrl: "http://api:4000/samlacs",
  sloUrl: "http://api:4000/samlslo",
  // SSRF guard (api/ssrf_guard.js). OFF here for the same reason as local.js:
  // on the compose network the identity provider (keycloak:8080) and the mock
  // STS (sts:8081) ARE private addresses, so the guard would refuse every call
  // this service exists to make. Deployed configurations leave it ON.
  blockPrivateNetworkCalls: false,
  // Outbound destinations this service refuses to call, as RANGES — a CIDR
  // block ("10.0.0.0/8") or a first-last pair ("10.0.0.0-10.255.255.255"). A
  // bare single address is refused with a logged reason: a network policy
  // written one host at a time almost always means the block that host sits in.
  // Replacing this list replaces the policy wholesale; omit it (or leave it
  // empty) to use the defaults baked into ssrf_guard.js, which are these.
  blockedAddressRanges: [
    "127.0.0.0/8",        // loopback
    "0.0.0.0/8",          // "this host on this network"
    "10.0.0.0/8",         // RFC 1918 private
    "172.16.0.0/12",      // RFC 1918 private
    "192.168.0.0/16",     // RFC 1918 private
    "169.254.0.0/16",
        // link-local, including 169.254.169.254 (cloud metadata)
    "100.64.0.0/10",      // RFC 6598 carrier-grade NAT
    "192.0.0.0/24",       // IETF protocol assignments
    "198.18.0.0/15",      // benchmarking
    "::1/128",            // IPv6 loopback
    "fe80::/10",          // IPv6 link-local
    "fc00::/7"            // IPv6 unique local
  ]
};

module.exports = config;
