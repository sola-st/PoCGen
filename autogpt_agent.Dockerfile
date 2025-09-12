FROM autogpt

ADD https://nodejs.org/dist/v22.10.0/node-v22.10.0-linux-x64.tar.xz /tmp/node.tar.xz

RUN apt-get update && apt-get install -y \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN tar -vxf /tmp/node.tar.xz -C /tmp && \
    mv /tmp/node-v22.10.0-linux-x64 /usr/bin/ && \
    ln -s /usr/bin/node-v22.10.0-linux-x64/bin/node /usr/bin/node && \
    ln -s /usr/bin/node-v22.10.0-linux-x64/bin/npm /usr/bin/npm \
    && rm -rf /tmp/node.tar.xz

COPY agent/code_executor.py /app/forge/forge/components/code_executor/code_executor.py
COPY agent/openai.py /app/forge/forge/llm/providers/openai.py

#COPY agent/openai.py /app/autogpt/venv/lib/python3.10/site-packages/forge/llm/providers/openai.py

