# Getting started

Running the debugger from a checkout and walking through the first OAuth 2.0 grants. To run the published images instead, see [Running the debugger](running.md).

If you have docker / docker-compose installed already:
```
git clone --recurse-submodules https://github.com/rcbj/id-proto-debugger.git
cd id-proto-debugger
sudo CONFIG_FILE=./env/local.js docker-compose build
./generate-tls-cert.sh                 # once per checkout: the TLS pair
sudo CONFIG_FILE=./env/local.js docker-compose up
```
Note, you will need at least 950MB of disk space ree in order to build this Docker image.

`--recurse-submodules` fetches the one submodule,
[`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs) at `api/node-ldapjs/`
(branch `master`): a fork of `ldapjs` for the LDAP support of issue #257, pinned
at the final commit its maintainer left behind when the project was
decommissioned on 2024-05-14 — which is why it is a submodule rather than a
dependency in `api/package.json`. An uninitialised submodule is an *empty
directory* rather than a missing one, so the api image builds and dies at
startup with `Cannot find module 'ldapjs'`. In a checkout cloned without it:
```
git submodule update --init
```
The test launchers do this for you (`requireApiLdapjsCheckout()` in
[`common/common.sh`](../common/common.sh)); a bare `docker-compose build` does not.

The mock STS the test suite and the local stack run against,
[`rcbj/iya-sts`](https://github.com/rcbj/iya-sts), is **not** a submodule: every
compose file runs its published release image — the private copy of
`ghcr.io/rcbj/iya-sts:<version>` in this repository's image mirror,
`ghcr.io/rcbj/id-proto-debugger/mirror/iya-sts:<version>`, which needs
`docker login ghcr.io` (see *The mock STS runs from its release image* below).

From a bash command prompt on Fedora or RHEL 7.x, run the following::
```
dnf install git # Or, yum install git
git clone --recurse-submodules https://github.com/rcbj/id-proto-debugger.git
dnf install docker
systemctl start docker
cd id-proto-debugger
sudo CONFIG_FILE=./env/local.js docker-compose build
./generate-tls-cert.sh                 # once per checkout: the TLS pair
sudo CONFIG_FILE=./env/local.js docker-compose up
```
## Clean Up / Start Over
This is a nuclear option to cleanup docker. You may not want to do this if you have other important things running on your site.

* List all containers (only IDs) ```sudo docker ps -aq```
* Stop all running containers: ```sudo docker stop $(docker ps -aq)```
* Remove all containers: ```sudo docker rm $(docker ps -aq)```
* Remove all images: ```sudo docker rmi $(docker images -q)```
* Prune volumes: ```sudo docker volume prune --all --force```
* Remove all volumes: ```sudo docker volume rm $(sudo docker volume ls | awk '{ print $2 }')```
* Remmove all networks: ```sudo docker network prune -f```

On other systems, the commands needed to start the debugger in a local docker container will be similar. The API container has to be able to establish connections to a remote IdP endpoint (whether locally in other docker containers, on the host VM, or over the network/internet). On the test system, it was necessary to add "--net=host" to the "docker run" args. The network connectivity details for docker may vary from platform-to-platform.

### Running
**Step-by-step guides with screenshots** for every OAuth2 grant and OIDC flow
are in [docs/oauth2-oidc](oauth2-oidc/index.md):
[OAuth 2.0 authorization grants](oauth2-oidc/oauth2-grants.md) and
[OpenID Connect authentication flows](oauth2-oidc/oidc-flows.md). The
summary below is the short version. The same guide covers [dynamic client registration](oauth2-oidc/dynamic-client-registration.md) and the [token detail, introspection, UserInfo, and JWKS pages](oauth2-oidc/related-tools.md). SAML 2.0 is [Using the SAML workflow](saml/index.md). WS-Trust is [Using the WS-Trust workflow](wstrust/index.md).

* Open your favorite browser and enter "https://localhost:3000" in the address bar.
* Choose the OAuth2 Grant or OIDC Flow that you want to test.
* Enter the Authorization Endpoint.
* Enter the Token Endpoint.
#### OAuth2 AUthorization Grant:
* Enter the client identifier.
* Enter the Redirect URI (use https://localhost:3000/callback by default)
* Enter the scope information.
* If you need to provide a resource parameter, click the radio button.  Then, enter the desired resource parameter.
* Click the Authorize button.  
* Authenticate the user.
* Scroll down to the "Exchange Authoriztaion Code for Access Token" Section.
* Verify that the Code field is filled in below in the Token Step section.
* Enter the client identifier
* Enter the client secret if this is a confidential client.
* Enter the scope information.
* If a resource is needed, click Yes.  Enter the resource information in the Resource field.
* If the provider's certificate is not in the API image's trust store, set **SSL Certificate Validation** to **No**. That switch applies when the token request is sent from the back end. A certificate from a public CA is checked against the trust store in the API container.
* Click the Get Token button.
* The standard tokens that are returned from the token endpoint are displayed at the bottom.
#### OAuth2 Implicit Grant:
* Enter the client identifier.
* Enter the Redirect URI  (use https://localhost:3000/callback by default)
* Enter the scope information.
* If you need to provide a resource parameter, click the radio button.  Then, enter the desired resource parameter.
* Click the Authorize button.
* Authenticate the user.  
* The access_token will be listed at the bottom of the screen.
#### Refresh Token Grant
 * In the configuration section, click the the "Yes" radio button next to "Use Refresh Token".  This will make the Refresh Token Section appear.
 * The refresh token is automatically populated from the Token Endpoint call response.
 * Enter the client identifier.
 * Enter the client secret.
 * Enter the scope.
 * Press Enter.
For the other grants and flows, similar steps to the above are used.

See the blog [posts](https://medium.com/@robert.broeckelmann/red-hat-sso-and-3scale-series-d904f2127702) for more information.


## Prerequisites

To run this project you will need to install docker.
