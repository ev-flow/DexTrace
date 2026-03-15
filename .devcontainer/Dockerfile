FROM mcr.microsoft.com/devcontainers/base:jammy

ARG DEBIAN_FRONTEND=noninteractive
ARG USER=vscode
ARG PYTHON_VERSION=3.10

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    make \
    ca-certificates \
    git \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    llvm \
    libncurses5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

USER ${USER}

ENV HOME=/home/${USER}
ENV PYENV_ROOT=${HOME}/.pyenv
ENV PATH=${PYENV_ROOT}/shims:${PYENV_ROOT}/bin:${HOME}/.local/bin:${PATH}

RUN curl https://pyenv.run | bash && \
    pyenv install ${PYTHON_VERSION} && \
    pyenv global ${PYTHON_VERSION} && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    poetry config virtualenvs.in-project true

WORKDIR /workspace