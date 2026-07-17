#!/bin/bash
set -x

check_return_code()
{
  rc=$1
  if [  $rc -ne 0 ];
  then
    echo "Non-zero return code. Exiting."
    exit 1
  fi
}

common_setup()
{
  echo "Entering common_setup()."
  REV=/usr/bin/rev
  JQ=/usr/bin/jq
  CURL=/usr/bin/curl
  for COMMAND in ${REV} ${JQ} ${CURL}
  do
    if [ ! -x "${COMMAND}" ];
    then
      echo "Cannot execute ${COMMAND} command."
      exit 1
    fi
  done
  echo "Leaving common_setup()."
}

docker_compose() {
  echo "Entering docker_compose()."
  if [ -x ~/.local/bin/docker-compose ];
  then 
    sudo CONFIG_FILE=${CONFIG_FILE} docker-compose "$@"
  elif docker compose version >/dev/null 2>&1; then
    sudo CONFIG_FILE=${CONFIG_FILE} docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    sudo CONFIG_FILE=${CONFIG_FILE} docker-compose "$@"
  else
    echo "Error: Docker Compose not found." >&2
    return 1
  fi
  echo "Leaving docker_compose()."
  return 0
}

configureKeycloak()
{
  echo "Entering configureKeycloak()."
  # Configure Keycloak
  KEYCLOAK_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" |\
    jq -r '.access_token')
  if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
  then
    echo "Failed to obtain access token." 
      exit 1
  fi
  
  curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"realm": "debugger-testing", "enabled": true}'
  check_return_code $?
  
  for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_CONFIDENTIAL AUTHORIZATION_CODE_PUBLIC IMPLICIT OIDC_AUTHORIZATION_CODE_CONFIDENTIAL OIDC_AUTHORIZATION_CODE_PUBLIC RESOURCE_OWNER_CREDENTIAL TOKEN_EXCHANGE_TARGET TOKEN_EXCHANGE DEVICE_AUTHORIZATION_GRANT TOKEN_INTROSPECTION
  do
    FLOW_NAME=$(echo ${FLOW_VARIABLE} | tr '[:upper:]' '[:lower:]' | tr '_' '-')

    KEYCLOAK_ACCESS_TOKEN=$(curl \
      -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=admin-cli" \
      -d "username=keycloak" \
      -d "password=keycloak" \
      -d "grant_type=password" \
      | jq -r '.access_token')
    if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
    then
      echo "KEYCLOAK_ACCESS_TOKEN is blank."
      exit 1
    fi
    curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "name": "'${FLOW_NAME}'-scope",
            "protocol": "openid-connect",
            "attributes": {
              "display.on.consent.screen": "false",
              "include.in.token.scope": "true"
            }
         }'
    check_return_code $?
    case "${FLOW_VARIABLE}" in
        CLIENT_CREDENTIALS)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                 "clientId": "'${FLOW_NAME}'",
                 "protocol": "openid-connect",
                 "publicClient": false,
                 "serviceAccountsEnabled": true,
                 "authorizationServicesEnabled": false,
                 "standardFlowEnabled": false,
                 "directAccessGrantsEnabled": false,
                 "clientAuthenticatorType": "client-secret",
                 "webOrigins": ["'${DEBUGGER_BASE_URL}'"]
               }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'", 
                   "protocol": "openid-connect", 
                   "publicClient": false, 
                   "serviceAccountsEnabled": false, 
                   "authorizationServicesEnabled": false, 
                   "standardFlowEnabled": true, 
                   "directAccessGrantsEnabled": false, 
                   "clientAuthenticatorType": "client-secret", 
                   "frontchannelLogout": true, 
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"], 
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"], 
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'", 
                "protocol": "openid-connect", 
                "publicClient": true, 
                "serviceAccountsEnabled": false, 
                "authorizationServicesEnabled": false, 
                "standardFlowEnabled": true, 
                "directAccessGrantsEnabled": false, 
                "clientAuthenticatorType": null, 
                "frontchannelLogout": true, 
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"], 
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"], 
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            ;;
        IMPLICIT)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": true,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "implicitFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": null,
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            check_return_code $?
            ;;
        OIDC_AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": true,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": null,
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            check_return_code $?
            ;;
        OIDC_AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        RESOURCE_OWNER_CREDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": false,
                   "directAccessGrantsEnabled": true,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        TOKEN_EXCHANGE_TARGET)
            # Audience (target) client for RFC 8693 token exchange. A token
            # exchange request can ask for a token aimed at this client via the
            # "audience" parameter.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        TOKEN_EXCHANGE)
            # Requesting client for RFC 8693 Standard Token Exchange (v2). It
            # obtains a subject token via the Authorization Code flow and then
            # exchanges it. Keycloak requires the requesting client to be in the
            # subject token's audience, so an audience mapper adds this client
            # (and the target client) to the access token's "aud" claim.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": true,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600,
                     "standard.token.exchange.enabled": "true"
                   },
                   "protocolMappers": [
                     {
                       "name": "token-exchange-self-audience",
                       "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper",
                       "config": {
                         "included.client.audience": "'${FLOW_NAME}'",
                         "id.token.claim": "false",
                         "access.token.claim": "true"
                       }
                     },
                     {
                       "name": "token-exchange-target-audience",
                       "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper",
                       "config": {
                         "included.client.audience": "token-exchange-target",
                         "id.token.claim": "false",
                         "access.token.claim": "true"
                       }
                     }
                   ]
                }'
            check_return_code $?
            ;;
        DEVICE_AUTHORIZATION_GRANT)
            # Public client with the OAuth 2.0 Device Authorization Grant
            # (RFC 8628) enabled. The device flow does not use a browser
            # redirect, so the standard/auth-code flow is disabled.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": true,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": false,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": null,
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "oauth2.device.authorization.grant.enabled": "true",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        TOKEN_INTROSPECTION)
            # Confidential Authorization Code client used by the Token
            # Introspection test. It is BOTH the client that signs in (via the
            # OIDC Authorization Code flow, to obtain the tokens) AND the client
            # that authenticates the RFC 7662 introspection calls. This is
            # required because Keycloak gates token introspection on the calling
            # client:
            #   - Access tokens: the client must be in the token's "aud", so an
            #     audience mapper adds this client to its own access tokens.
            #   - Refresh tokens: the client must be the one the token was issued
            #     to (azp); no audience mapper or role grants cross-client
            #     refresh-token introspection. A public client cannot call the
            #     introspection endpoint at all.
            # A single confidential client that owns the tokens and is in their
            # audience is therefore the only setup for which all of the debugger's
            # Introspect Token links report "active": true.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": false,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": "client-secret",
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                },
                "protocolMappers": [
                  {
                    "name": "token-introspection-self-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                      "included.client.audience": "'${FLOW_NAME}'",
                      "id.token.claim": "false",
                      "access.token.claim": "true"
                    }
                  }
                ]
             }'
            check_return_code $?
            ;;
    esac

    CLIENT_ID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].id')
    CLIENT_CLIENTID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].clientId')
    CLIENT_SECRET=$(curl  \
      -X GET \
     "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
     | jq -r '.[0].secret')
    SCOPE_ID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .id')
    SCOPE_NAME=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .name')
    curl \
     -X PUT \
     "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients/${CLIENT_ID}/optional-client-scopes/${SCOPE_ID}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}"
    check_return_code $?
    USER_ID=$(curl \
      -X POST \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{ 
            "username": "'${FLOW_NAME}'",
            "firstName": "'${FLOW_NAME}'", 
            "lastName": "'${FLOW_NAME}'", 
            "email": "'${FLOW_NAME}'@iyasec.io", 
            "enabled": true, "emailVerified": true
          }' \
      -i \
      | grep Location \
      | rev \
      | cut -d '/' -f 1 \
      | rev \
      | tr -d ' \n\r')
    if [ -z "${CLIENT_ID}" ] || \
       [ -z "${CLIENT_CLIENTID}" ] || \
       [ -z "${CLIENT_SECRET}" ] || \
       [ -z "${SCOPE_ID}" ] || \
       [ -z "${SCOPE_NAME} ] || \
       [ -z "${USER_ID} ];
    then
      echo "Required variable is blank."
      exit 1
    fi 
    curl \
      -X PUT \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users/${USER_ID}/reset-password" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "type": "password",
            "value": "'${FLOW_NAME}'",
            "temporary": false
          }'
    check_return_code $?

    # -gx (export) so child processes — e.g. tests/run-report.js — inherit these
    declare -gx ${FLOW_VARIABLE}_AUDIENCE="${KEYCLOAK_BASE_URL}/realms/debugger-testing"
    declare -gx ${FLOW_VARIABLE}_DISCOVERY_ENDPOINT="${KEYCLOAK_BASE_URL}/realms/debugger-testing/.well-known/openid-configuration"
    declare -gx ${FLOW_VARIABLE}_CLIENT_ID="${CLIENT_CLIENTID}"
    declare -gx ${FLOW_VARIABLE}_CLIENT_SECRET="${CLIENT_SECRET}"
    declare -gx ${FLOW_VARIABLE}_SCOPE="${SCOPE_NAME}"
    declare -gx ${FLOW_VARIABLE}_USER="${USER_ID}"

  done

  # ---- OIDC Dynamic Client Registration --------------------------------------
  # Mint an initial access token so the Dynamic Client Registration test can
  # create clients. Keycloak requires an initial access token for authenticated
  # registration (anonymous registration is blocked by the default trusted-hosts
  # policy). The test then reads/updates/deletes the client it creates using the
  # registration access token returned at registration (RFC 7592).
  KEYCLOAK_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" \
    | jq -r '.access_token')
  if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
  then
    echo "KEYCLOAK_ACCESS_TOKEN is blank."
    exit 1
  fi
  DCR_INITIAL_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients-initial-access" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{ "count": 10, "expiration": 86400 }' \
    | jq -r '.token')
  if [ -z "${DCR_INITIAL_ACCESS_TOKEN}" ] || [ "${DCR_INITIAL_ACCESS_TOKEN}" = "null" ];
  then
    echo "Failed to mint a Dynamic Client Registration initial access token."
    exit 1
  fi
  declare -gx DYNAMIC_CLIENT_REGISTRATION_DISCOVERY_ENDPOINT="${KEYCLOAK_BASE_URL}/realms/debugger-testing/.well-known/openid-configuration"
  declare -gx DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN="${DCR_INITIAL_ACCESS_TOKEN}"

  echo "Leaving configureKeycloak()."
}
