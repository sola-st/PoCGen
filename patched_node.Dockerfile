FROM ubuntu:22.04

ENV NODE_VERSION=22.11.0 \
    PATCH_FILE=v8.patch \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    python3 \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION.tar.gz -o /tmp/node.tar.gz && \
    tar -xzvf /tmp/node.tar.gz -C /tmp && \
    cd /tmp/node-v$NODE_VERSION

WORKDIR /tmp/node-v$NODE_VERSION

COPY $PATCH_FILE /tmp/$PATCH_FILE

RUN patch -p1 < /tmp/$PATCH_FILE && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/*

RUN node -v && npm -v

CMD ["/bin/bash"]
