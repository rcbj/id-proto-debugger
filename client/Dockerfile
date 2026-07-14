#FROM node:lts
FROM ubuntu:latest
        
ARG CONFIG_FILE

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/app

RUN apt-get update
RUN apt-get -y install curl \
        jq \
        wget \
        unzip \ 
        util-linux \
        bsdextrautils

# Install NVM
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash

# Load NVM and install Node.js
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN cat ~/.bashrc

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# add node and npm to path so the commands are available
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# confirm installation
RUN node -v
RUN npm -v
    
# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY client/package.json client/package-lock.json /usr/src/app/
RUN npm ci && npm cache clean --force
RUN npm install -g browserify
#RUN npm install -g node-gyp

# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY client/public/ /usr/src/app/public/
#COPY dist/ /usr/src/app/public/dist/
COPY client/src/env/ /usr/src/app/env/
COPY client/server.js /usr/src/app
COPY client/package.json /usr/src/app
RUN true
COPY client/src/ /usr/src/app/src/
RUN true
COPY client/src/env/ /usr/src/app/public/js/env/
COPY common/data.js /usr/src/app/src
RUN browserify src/jwks.js -o public/js/jwks.js --debug --standalone jwks -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/debugger.js -o public/js/debugger.js --debug --standalone debug -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/token_detail.js -o public/js/token_detail.js --debug --standalone token_detail -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/debugger2.js -o public/js/debugger2.js --debug --standalone debugger2 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/userinfo.js -o public/js/userinfo.js --debug --standalone userinfo -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/introspection.js -o public/js/introspection.js --debug --standalone introspection -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]

RUN browserify src/logout.js -o public/js/logout.js --debug --standalone logout -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/jwt_tools.js -o public/js/jwt_tools.js --debug --standalone jwt_tools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
#COPY src/debugger2_js.js public/js

# ---- Code coverage (opt-in) ----
# When built with --build-arg COVERAGE=true, re-build the bundles with Istanbul
# instrumentation (babel-plugin-istanbul) and append the coverage beacon so the
# browser ships its coverage to the client server. The default build
# (COVERAGE=false) leaves the bundles produced above completely untouched.
ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then \
      npm install --no-save babelify babel-plugin-istanbul @babel/core nyc ; \
    fi
RUN if [ "$COVERAGE" = "true" ]; then \
      for entry in "jwks:jwks" "debugger:debug" "token_detail:token_detail" "debugger2:debugger2" "userinfo:userinfo" "introspection:introspection" "logout:logout" "jwt_tools:jwt_tools"; do \
        src_name="${entry%%:*}" ; \
        standalone="${entry##*:}" ; \
        browserify src/${src_name}.js -o public/js/${src_name}.js --debug --standalone ${standalone} -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ] -t [ babelify --plugins [ istanbul ] ] && \
        cat src/coverage_beacon.js >> public/js/${src_name}.js ; \
      done ; \
    fi

EXPOSE 3000
CMD [ "npm", "start" ]
