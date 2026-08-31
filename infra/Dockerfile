# Terraform runner image for the idptools infrastructure.
#
# Same base pattern as deploy/Dockerfile (Ubuntu + AWS CLI v2), plus a pinned
# Terraform. Runs init/plan/apply/destroy for a chosen environment via
# infra/entrypoint.sh. Used identically on a developer machine
# (infra/terraform-local.sh) and in GitHub Actions (.github/workflows/terraform.yml).
FROM ubuntu:latest

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

WORKDIR /workspace

# ONE RUN, deliberately: see the note above the same pair in
# tests/Dockerfile. A cached `RUN apt-get update` layer keeps naming package
# versions the archive pool has already superseded and dropped, and the
# install below then 404s on every -updates/-security package at once — a
# failure that reads as a broken mirror and is not one.
RUN apt-get update \
    && apt-get -y install curl \
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

# ---------------------------------------------------------------------------
# NON-ROOT FROM HERE ON. See the same block in api/Dockerfile for why the UID
# is 10001 rather than 1000 (ubuntu:latest already has an account at 1000).
#
# /workspace has to be writable by that user and not merely readable, which is
# what separates this image from the other four: `terraform init` writes
# .terraform/ and .terraform.lock.hcl INSIDE the configuration directory, and
# a plan writes its own file there. State is remote (S3), so nothing else
# persists — terraform-local.sh mounts no volume at all.
#
# HOME for the same reason deploy/Dockerfile needs one: the AWS CLI caches
# credentials under it, and terraform's provider cache lives there too.
# ---------------------------------------------------------------------------
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && chown -R appuser:appuser /workspace

ENV HOME=/home/appuser
USER appuser

ENTRYPOINT ["/workspace/infra/entrypoint.sh"]
