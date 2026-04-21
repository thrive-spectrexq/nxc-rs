FROM mcr.microsoft.com/devcontainers/rust:1

# Install required system dependencies for nxc-rs
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        libkrb5-dev \
        libsasl2-dev \
        libldap2-dev \
        pkg-config \
        libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
