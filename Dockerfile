FROM patched_node

RUN apt-get update && apt-get install -y curl cloc

RUN apt-get install -y docker.io

ADD https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz /tmp/c.tgz

RUN mkdir /opt/codeql \
    && cd /opt/codeql \
    && tar -xvf /tmp/c.tgz \
    && rm /tmp/c.tgz

ENV PATH="/opt/codeql/codeql:${PATH}"

COPY src/resources/genpoc.c /tmp/genpoc.c
RUN gcc /tmp/genpoc.c -o /usr/bin/genpoc && rm /tmp/genpoc.c && chmod 4555 /usr/bin/genpoc

RUN pip install --pre mini-swe-agent

RUN touch /flag.txt && chmod 777 /flag.txt

RUN npm install -g typescript

RUN useradd -m -u 1000 -s /bin/bash node

USER node

WORKDIR /app

ENTRYPOINT [ ]
