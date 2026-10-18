# tentaclai – sandbox + service gateway for Claude Code
# Tools: Claude Code, Docker CLI + compose, git, python, node, ssh, jq, ripgrep
FROM node:26-bookworm-slim

ARG CLAUDE_CODE_VERSION=latest

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    # Updates come via image rebuild, not in-place (npm prefix is not persisted)
    DISABLE_AUTOUPDATER=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git jq ripgrep fd-find less nano vim-tiny tmux \
        openssh-client rsync unzip zip procps iputils-ping dnsutils \
        python3 python3-venv python3-pip make \
        postgresql-client mariadb-client \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    # Docker CLI + compose plugin (talks to the host daemon via the mounted socket)
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
        > /etc/apt/sources.list.d/docker.list \
    # GitHub CLI (uses GH_TOKEN from .env)
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod a+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        docker-ce-cli docker-compose-plugin docker-buildx-plugin gh \
    && rm -rf /var/lib/apt/lists/*

# CACHE_BUST (set by tentacontrol on update) forces a fresh npm install of the latest version
ARG CACHE_BUST=0
RUN echo "cache bust: ${CACHE_BUST}" && npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
    && npm cache clean --force

COPY entrypoint.sh start.sh rc-loop cc svc claude-instructions tc-scan /usr/local/bin/
COPY CLAUDE.base.md /etc/tentaclai/CLAUDE.base.md
COPY commands/ /etc/tentaclai/commands/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/start.sh /usr/local/bin/rc-loop /usr/local/bin/cc /usr/local/bin/svc /usr/local/bin/claude-instructions /usr/local/bin/tc-scan \
    # tmux: mouse scrolling, bigger scrollback, truecolor for Claude's TUI
    && printf '%s\n' 'set -g mouse on' 'set -g history-limit 50000' \
        'set -g default-terminal "tmux-256color"' 'set -ga terminal-overrides ",*:Tc"' > /etc/tmux.conf

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/start.sh"]
