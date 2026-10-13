# syntax=docker/dockerfile:1
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG ENVIRONMENT_REFRESH
ARG INSTALL_QEMU=0
COPY scripts/prepare-linux-test.sh /opt/filecrypt/environment/prepare-linux-test.sh
RUN test -n "$ENVIRONMENT_REFRESH" \
    && bash /opt/filecrypt/environment/prepare-linux-test.sh "$INSTALL_QEMU"
WORKDIR /workspace
