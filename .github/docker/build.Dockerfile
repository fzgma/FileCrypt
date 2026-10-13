# syntax=docker/dockerfile:1
ARG BASE_IMAGE=quay.io/pypa/manylinux_2_28_x86_64
FROM ${BASE_IMAGE}

# 每周更新仓库软件包；项目源码不参与环境层的缓存失效。
ARG ENVIRONMENT_REFRESH
RUN test -n "$ENVIRONMENT_REFRESH" \
    && dnf install -y gcc-toolset-15-gcc gcc-toolset-15-gcc-c++ \
        gcc-toolset-15-libstdc++-devel gcc-toolset-15-binutils \
    && dnf clean all
ENV PATH="/opt/python/cp312-cp312/bin:${PATH}"
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    cmake==3.31.6 ninja==1.11.1.3

COPY scripts/setup-gcc15.sh scripts/linux-deps.env scripts/build-linux-deps.sh /opt/filecrypt/environment/
RUN bash /opt/filecrypt/environment/build-linux-deps.sh
ENV FILECRYPT_DEPS_PREFIX=/opt/filecrypt/deps
WORKDIR /workspace
