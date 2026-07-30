# Keycloak 8.0.1 (WildFly) + cloudtrust keycloak-wsfed module.
#
# DEDICATED side-car IdP for the WS-Federation debugger test. The main stack runs
# Keycloak 26.6.4 (Quarkus), which has no WS-Federation support; the
# cloudtrust/keycloak-wsfed extension only targets Keycloak 8.0.1 (WildFly). It
# implements the WS-Federation 1.2 Web (Passive) Requestor profile (SAML 1.1/2.0).
#
# We install the Keycloak 8.0.1 SERVER DISTRIBUTION from its archive onto a modern
# base image, rather than pulling the 2019 quay.io/keycloak/keycloak:8.0.1 image —
# that image's legacy Docker Schema-1 manifest ("v1+prettyjws") is rejected by
# modern Docker/containerd (v2.1+) and by CI runners. Keycloak 8 / WildFly 18 runs
# on Java 11, and eclipse-temurin:11-jdk ships a current OCI manifest that pulls
# everywhere. Base path /auth; HTTP on 8080; on host-network stacks the compose
# command adds a WildFly port-offset so it doesn't collide with the 26.x Keycloak
# (8080) or STS (8081).
FROM eclipse-temurin:11-jdk

# Overridable so a mirror/pinned copy can be substituted at build time.
ARG KEYCLOAK_DIST_URL=https://downloads.jboss.org/keycloak/8.0.1/keycloak-8.0.1.tar.gz
ARG WSFED_TARBALL_URL=https://github.com/cloudtrust/keycloak-wsfed/releases/download/8.0.1-1.0/keycloak-wsfed-8.0.1-1.0.tar.gz

ENV JBOSS_HOME=/opt/jboss/keycloak
# The admin is created offline at build time (below); these are the credentials
# common.sh's configureKeycloakWsfed() authenticates with.
ENV KEYCLOAK_USER=keycloak
ENV KEYCLOAK_PASSWORD=keycloak

# xmlstarlet + getopt(util-linux) + find(findutils) are needed by the module's
# vendored install.sh, which edits standalone.xml namespace-correctly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tar gzip xmlstarlet util-linux findutils \
    && rm -rf /var/lib/apt/lists/*

# Install the Keycloak 8.0.1 server distribution into $JBOSS_HOME.
RUN mkdir -p /opt/jboss \
    && curl -fSL --retry 5 --retry-all-errors -o /tmp/keycloak.tar.gz "${KEYCLOAK_DIST_URL}" \
    && tar xzf /tmp/keycloak.tar.gz -C /opt/jboss \
    && mv /opt/jboss/keycloak-8.0.1 "${JBOSS_HOME}" \
    && rm /tmp/keycloak.tar.gz

# Take AUTO_SERVER off the H2 datasource URL.
#
# Keycloak 8 ships `jdbc:h2:${jboss.server.data.dir}/keycloak;AUTO_SERVER=TRUE`.
# AUTO_SERVER puts H2 in automatic mixed mode: it opens a server socket so other
# processes can share the database, and to advertise that socket it resolves its
# OWN HOSTNAME. Nothing shares this database — it is one throwaway container — and
# under host networking the container's hostname need not resolve at all, in which
# case H2 throws UnknownHostException, the KeycloakDS datasource never binds, and
# the entire boot is rolled back:
#
#   Caused by: org.h2.jdbc.JdbcSQLException: IO Exception:
#     "java.net.UnknownHostException: keycloak-wsfed: No address associated with hostname"
#   Caused by: java.lang.RuntimeException: Failed to connect to database
#
# What is visible at the END of that log is a NullPointerException in the
# microprofile-metrics subsystem, which is only the rollback tripping over
# services that were already removed — not the cause.
#
# Guarded on both sides: the build fails if the pattern is not there to change
# (a newer Keycloak would need this revisited) and fails if any AUTO_SERVER
# survives the edit.
RUN CFG="${JBOSS_HOME}/standalone/configuration/standalone.xml" \
    && grep -q 'AUTO_SERVER=TRUE' "${CFG}" \
    && sed -i 's|jdbc:h2:${jboss.server.data.dir}/keycloak;AUTO_SERVER=TRUE|jdbc:h2:${jboss.server.data.dir}/keycloak|' "${CFG}" \
    && ! grep -q 'AUTO_SERVER' "${CFG}"

# Create the master-realm admin offline (WildFly imports keycloak-add-user.json
# on first boot). No running server needed.
RUN "${JBOSS_HOME}/bin/add-user-keycloak.sh" -r master -u "${KEYCLOAK_USER}" -p "${KEYCLOAK_PASSWORD}"

# Download + unpack the WS-Federation module distribution (install.sh + module.xml
# + target/keycloak-wsfed-8.0.1.jar under "Keycloak WS-Fed Integration/").
RUN curl -fSL --retry 5 --retry-all-errors -o /tmp/wsfed.tar.gz "${WSFED_TARBALL_URL}" \
    && mkdir -p /tmp/wsfed \
    && tar xzf /tmp/wsfed.tar.gz -C /tmp/wsfed

# Install + register the module (xmlstarlet-free, verified — see the script).
COPY keycloak-wsfed/install-wsfed.sh /tmp/install-wsfed.sh
RUN chmod +x /tmp/install-wsfed.sh \
    && /tmp/install-wsfed.sh "${JBOSS_HOME}" \
    && rm -rf /tmp/wsfed /tmp/wsfed.tar.gz /tmp/install-wsfed.sh

EXPOSE 8080
# standalone.sh receives the bind address + any -D overrides (e.g. the
# -Djboss.socket.binding.port-offset=2 the host-network compose file appends).
ENTRYPOINT ["/opt/jboss/keycloak/bin/standalone.sh"]
CMD ["-b", "0.0.0.0"]
