# ============================================================
# Attacker Workstation — Kali-slim + API Security Tooling
# ============================================================
FROM kalilinux/kali-rolling:latest

LABEL maintainer="Ronald Maboufotso"
LABEL description="Pre-configured attacker for API security testing"

ENV DEBIAN_FRONTEND=noninteractive

# Core tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    httpie \
    ffuf \
    nmap \
    netcat-openbsd \
    vim \
    tmux \
    && rm -rf /var/lib/apt/lists/*

# Python tooling
RUN pip3 install --no-cache-dir --break-system-packages \
    requests \
    jwt \
    pyjwt \
    httpx \
    rich \
    faker \
    python-dotenv

# jwt_tool — JWT attack Swiss Army knife
RUN git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip3 install --no-cache-dir --break-system-packages termcolor cprint pycryptodomex requests \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# Newman (Postman CLI runner)
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && npm install -g newman \
    && rm -rf /var/lib/apt/lists/*

# Working directories
RUN mkdir -p /opt/scripts /opt/reports /opt/wordlists

# Common API wordlists
RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt \
    -O /opt/wordlists/api-endpoints.txt || true

RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt \
    -O /opt/wordlists/api-objects.txt || true

WORKDIR /opt/scripts

# Helpful aliases
RUN echo 'alias ll="ls -la"' >> /root/.bashrc \
    && echo 'alias crapi="curl -s $CRAPI_URL"' >> /root/.bashrc \
    && echo 'alias vampi="curl -s $VAMPI_URL"' >> /root/.bashrc \
    && echo 'export PS1="[attacker]\\$ "' >> /root/.bashrc

CMD ["/bin/bash"]
