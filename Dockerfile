FROM cruizba/ubuntu-dind:noble-latest

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
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
    sudo \
    tmux \
    universal-ctags \
    wget

RUN sudo install -m 0755 -d /etc/apt/keyrings
RUN sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
RUN sudo chmod a+r /etc/apt/keyrings/docker.asc
RUN echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN DEBIAN_FRONTEND=noninteractive  apt-get update && apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3.12-venv && python3 -m venv /opt/venv
ENV PATH "/opt/venv/bin:$PATH"

RUN pip install \
    colorama \
    clang==16.0.1 \
    GitPython \
    langchain-community==0.3.18 \
    langchain-core==0.3.39 \
    langchain-experimental==0.3.4 \
    langchain-openai==0.3.7 \
    langchain==0.3.19 \
    litellm \
    ipdb \
    matplotlib \
    openai \
    openpyxl \
    pika \
    prettytable \
    psycopg2-binary \
    python-dotenv \
    sqlalchemy \
    unidiff

ENV LC_CTYPE=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /patchagent-package
COPY patchagent /patchagent-package/patchagent
ENV PYTHONPATH "/patchagent-package:$PYTHONPATH"
