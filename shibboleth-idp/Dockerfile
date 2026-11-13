# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# Shibboleth Identity Provider 4.3.3 on Jetty 10.0.22.
#
# A SAML 1.1 PEER for tests/saml11_peers.js: the one widely deployed
# identity provider that still answers Shibboleth's AuthnRequest profile
# (/idp/profile/Shibboleth/SSO: providerId, shire, target, time) with a
# SAML 1.1 Browser/POST response. iya-sts answers the same profile; this
# is somebody else's implementation of it. See shibboleth-idp/CLAUDE.md.
#
# 4.3.3 is the release this configuration was proven against, with the
# SAML 1.1 profiles in its core and Java 11 as its floor. Jetty 10 is the
# newest Jetty a V4 IdP runs on: it is javax.servlet, and Jetty 11 and
# later are jakarta.servlet.
#
# Both archives are downloaded from their official locations and checked
# against a pinned SHA-256. Shibboleth publishes that digest beside the
# archive; Maven Central publishes only a SHA-1 for jetty-home, so the
# SHA-256 below was computed from the archive whose SHA-1 matched it
# (26e8e5b8bf3501798162303713463476c9db0614).
FROM eclipse-temurin:11-jdk

ARG IDP_VERSION=4.3.3
ARG IDP_SHA256=815abe9c707c8741278eda8b9120be7d99f09238d2974ccc3a93b37d549cc149
ARG IDP_URL=https://shibboleth.net/downloads/identity-provider/${IDP_VERSION}/shibboleth-identity-provider-${IDP_VERSION}.tar.gz
ARG JETTY_VERSION=10.0.22
ARG JETTY_SHA256=e4217cc1f9e501b7a17fd9a568858785925bcf5d490c3dac8a9f97123779cd8c
ARG JETTY_URL=https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-home/${JETTY_VERSION}/jetty-home-${JETTY_VERSION}.tar.gz

ENV IDP_HOME=/opt/shibboleth-idp
ENV JETTY_HOME=/opt/jetty-home
ENV JETTY_BASE=/opt/jetty-base

# curl downloads the archives and is the compose healthcheck's probe.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fSL --retry 5 --retry-all-errors -o /tmp/idp.tar.gz "${IDP_URL}" \
    && echo "${IDP_SHA256}  /tmp/idp.tar.gz" | sha256sum -c - \
    && curl -fSL --retry 5 --retry-all-errors -o /tmp/jetty.tar.gz \
        "${JETTY_URL}" \
    && echo "${JETTY_SHA256}  /tmp/jetty.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/idp-src "${JETTY_HOME}" \
    && tar xzf /tmp/idp.tar.gz -C /tmp/idp-src --strip-components=1 \
    && tar xzf /tmp/jetty.tar.gz -C "${JETTY_HOME}" --strip-components=1 \
    && rm /tmp/idp.tar.gz /tmp/jetty.tar.gz

# Non-interactive install. The installer generates the signing,
# encryption and back-channel key pairs and the data sealer here, at
# image build, so every container of one image shares them; nothing
# outside this throwaway stack trusts them. The passwords protect only
# the generated PKCS#12 and sealer keystores inside the image.
COPY shibboleth-idp/idp-merge.properties /tmp/idp-merge.properties
RUN cd /tmp/idp-src \
    && bin/install.sh \
        -Didp.src.dir=/tmp/idp-src \
        -Didp.target.dir="${IDP_HOME}" \
        -Didp.host.name=shibboleth-idp \
        -Didp.scope=example.test \
        -Didp.entityID=http://shibboleth-idp:8080/idp/shibboleth \
        -Didp.keystore.password=shibboleth-test-keystore \
        -Didp.sealer.password=shibboleth-test-sealer \
        -Didp.merge.properties=/tmp/idp-merge.properties \
        -Didp.noprompt=true \
    && rm -rf /tmp/idp-src /tmp/idp-merge.properties \
    && test -f "${IDP_HOME}/war/idp.war" \
    && test -f "${IDP_HOME}/credentials/idp-signing.key"

# The configuration this stack needs, over the installer's defaults.
# The XML files are Shibboleth's own, edited; each change is listed in
# shibboleth-idp/CLAUDE.md.
COPY shibboleth-idp/conf/ ${IDP_HOME}/conf/
COPY shibboleth-idp/credentials/demo.htpasswd \
    ${IDP_HOME}/credentials/demo.htpasswd
COPY shibboleth-idp/metadata/debugger-saml11-sp.xml \
    ${IDP_HOME}/metadata/debugger-saml11-sp.xml

# The Jetty base: the modules the V4 IdP needs, HTTP on 8080, and a
# context descriptor that deploys the war where the installer left it.
RUN mkdir -p "${JETTY_BASE}/webapps" \
    && cd "${JETTY_BASE}" \
    && java -jar "${JETTY_HOME}/start.jar" --approve-all-licenses \
        --add-modules=server,http,deploy,annotations,jsp,jstl \
        --add-modules=plus,servlets,ext,webapp \
    && sed -i 's|^# *jetty.http.port=.*|jetty.http.port=8080|' \
        start.d/http.ini \
    && grep -q '^jetty.http.port=8080' start.d/http.ini
COPY shibboleth-idp/jetty/idp.xml ${JETTY_BASE}/webapps/idp.xml

# ---------------------------------------------------------------------------
# NON-ROOT FROM HERE ON, uid/gid 10001 like every image this repository
# builds (see "Containers run as non-root" in the root CLAUDE.md).
#
# The IdP writes its logs under $IDP_HOME/logs and Jetty writes under
# $JETTY_BASE; both trees are handed over whole. Jetty unpacks the war's
# WEB-INF into java.io.tmpdir (/tmp), which is world-writable already.
# 8080 is above 1024 and needs no capability.
# ---------------------------------------------------------------------------
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && chown -R appuser:appuser "${IDP_HOME}" "${JETTY_BASE}"

ENV HOME=/home/appuser
USER appuser
WORKDIR /opt/jetty-base

EXPOSE 8080
ENV JAVA_OPTS="-Xmx768m"
# idp.home is baked into the war by the installer; it is set again here
# so a mistaken war still finds its configuration.
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -Didp.home=/opt/shibboleth-idp -jar /opt/jetty-home/start.jar"]
