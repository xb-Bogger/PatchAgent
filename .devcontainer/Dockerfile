FROM ubuntu:24.04

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
    black \
    colorama \
    clang==16.0.1 \
    flake8 \
    GitPython \
    isort \
    langchain-community \
    langchain-core \
    langchain-experimental \
    langchain-openai \
    langchain \
    litellm \
    ipdb \
    matplotlib \
    openai \
    openpyxl \
    pika \
    prettytable \
    pre-commit \
    psycopg2-binary \
    python-dotenv \
    sqlalchemy \
    unidiff

ENV LC_CTYPE=C.UTF-8
ENV LANG=C.UTF-8

RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
RUN sudo apt-get install git-lfs
