FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    cloc \
    build-essential \
    python3 \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ADD https://nodejs.org/dist/v22.10.0/node-v22.10.0-linux-x64.tar.xz /tmp/node.tar.xz

RUN tar -vxf /tmp/node.tar.xz -C /tmp

RUN mv /tmp/node-v22.10.0-linux-x64 /usr/bin/

RUN ln -s /usr/bin/node-v22.10.0-linux-x64/bin/node /usr/bin/node

RUN ln -s /usr/bin/node-v22.10.0-linux-x64/bin/npm /usr/bin/npm

RUN useradd -m -u 1000 -s /bin/bash node

ADD https://download.docker.com/linux/static/stable/x86_64/docker-24.0.4.tgz /tmp/docker.tgz

RUN tar -xvzf /tmp/docker.tgz -C /tmp && \
    cp /tmp/docker/docker* /usr/bin/ && \
    rm -rf /tmp/docker*

USER node

WORKDIR /app

ENTRYPOINT [ ]
