# Terraform runner image for the idptools infrastructure.
#
# Same base pattern as deploy/Dockerfile (Ubuntu + AWS CLI v2), plus a pinned
# Terraform. Runs init/plan/apply/destroy for a chosen environment via
# infra/entrypoint.sh. Used identically on a developer machine
# (infra/terraform-local.sh) and in GitHub Actions (.github/workflows/terraform.yml).
FROM ubuntu:latest

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

WORKDIR /workspace

RUN apt-get update
RUN apt-get -y install curl \
        jq \
        wget \
        unzip \
        ca-certificates \
        util-linux \
        bsdextrautils

# --- AWS CLI v2 (self-contained) ---
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && aws --version

# --- Terraform (pinned; >= 1.11 for S3-native state locking) ---
ARG TERRAFORM_VERSION=1.15.8
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -o /tmp/tf.zip \
    && unzip -q /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip \
    && terraform version

# --- Terraform configs + entrypoint ---
COPY infra/ /workspace/infra/
RUN chmod +x /workspace/infra/entrypoint.sh

ENTRYPOINT ["/workspace/infra/entrypoint.sh"]
