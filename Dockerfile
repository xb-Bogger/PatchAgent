FROM cruizba/ubuntu-dind:noble-latest

RUN DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    clang-16 \
    clangd \
    cmake \
    curl \
    gdb \
    git \
    lld \
    make \
    pkg-config \
    python3 \
    python3-pip \
    python3.12-venv \
    sudo \
    tmux \
    universal-ctags \
    wget && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin && \
    python3 -m venv /opt/venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PATH "/opt/venv/bin:$PATH"

COPY patchagent /source/patchagent
COPY pyproject.toml /source/pyproject.toml

RUN cd /source && pip install --no-cache-dir .
