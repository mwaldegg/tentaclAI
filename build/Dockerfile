# tentaclai – sandbox + service gateway for Claude Code
# Tools: Claude Code, git, python, node, ssh, jq, ripgrep, database clients, gh, compilers, uv, Playwright + Chromium –
# docker runs on the hosts over SSH (svc)
FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=latest
# npm and pip package must have the same version: both use the browser build in /opt/pw-browsers
ARG PLAYWRIGHT_VERSION=1.64.1

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    # Updates come via image rebuild, not in-place (npm prefix is not persisted)
    DISABLE_AUTOUPDATER=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git jq ripgrep fd-find less nano vim-tiny tmux \
        openssh-client rsync unzip zip procps iputils-ping dnsutils \
        python3 python3-venv python3-pip make \
        postgresql-client mariadb-client sshpass sudo bash-completion \
        poppler-utils sqlite3 shellcheck imagemagick build-essential python3-dev \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    # GitHub CLI (public data only – the GitHub service goes through svc)
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod a+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        gh \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /uvx /usr/local/bin/
# pnpm through corepack (fetched on first use); no prompt – it would wait on stdin
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable pnpm

# Headless Chromium for screenshots and browser tests (tc-shot, Playwright for Node and Python), before CACHE_BUST so a
# Claude Code update doesn't fetch it again. Only the headless shell – no display here. /opt/pw-browsers/chromium is the
# executablePath for projects that pin another Playwright version. Its libraries by hand instead of --with-deps (which
# adds xvfb, Mesa/LLVM and CJK fonts, ~250 MB) – the self-test below fails the build if one is missing. Python's
# package runs on the image's node instead of its own copy (~120 MB).
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    NODE_PATH=/usr/local/lib/node_modules
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnss3 libglib2.0-0 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 libdbus-1-3 libxcomposite1 libxdamage1 \
        libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libasound2 \
        fonts-dejavu fonts-liberation fonts-noto-color-emoji \
    && npm install -g playwright@${PLAYWRIGHT_VERSION} \
    && playwright install --only-shell chromium \
    && pip3 install --no-cache-dir --break-system-packages playwright==${PLAYWRIGHT_VERSION} \
    && ln -sf /usr/local/bin/node /usr/local/lib/python3.11/dist-packages/playwright/driver/node \
    && ln -s "$(find /opt/pw-browsers -type f \( -name chrome-headless-shell -o -name headless_shell \) | head -1)" /opt/pw-browsers/chromium \
    && test -x /opt/pw-browsers/chromium \
    && chmod -R a+rX /opt/pw-browsers \
    && rm -rf /var/lib/apt/lists/* && npm cache clean --force
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# CACHE_BUST (set by tentacontrol on update) forces a fresh npm install of the latest version
ARG CACHE_BUST=0
RUN echo "cache bust: ${CACHE_BUST}" && npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
    && npm cache clean --force

COPY build/entrypoint.sh build/start.sh build/rc-loop build/cc build/svc build/claude-instructions build/tc-scan build/tc-statusline build/tc-connect build/tc-guard build/tc-shot /usr/local/bin/
COPY lib/tclib.py /usr/local/lib/tentaclai/tclib.py
COPY build/svclib/ /usr/local/lib/tentaclai/svclib/
RUN python3 -m compileall -q /usr/local/lib/tentaclai
COPY build/svc-completion.bash /etc/bash_completion.d/svc
COPY VERSION /etc/tentaclai/VERSION
COPY build/CLAUDE.base.md /etc/tentaclai/CLAUDE.base.md
COPY build/commands/ /etc/tentaclai/commands/
# Users: claude = the agent (no secrets, no keys), tcrun = client tools started by svc (one secret at a time).
# Root holds .env, SSH keys and service files; Claude reaches them only through `svc`/`tc-scan` via sudo.
ARG CLAUDE_UID=10000
RUN groupadd -g ${CLAUDE_UID} claude && useradd -m -d /home/claude -u ${CLAUDE_UID} -g claude -s /bin/bash claude \
    && groupadd -g 10001 tcrun && useradd -m -d /var/lib/tcrun -u 10001 -g tcrun -s /usr/sbin/nologin tcrun \
    && chmod 700 /var/lib/tcrun \
    # env_keep: only these four names – where a request comes from (session, tmux pane), never
    # CLAUDE_CODE_SESSION_ACCESS_TOKEN or anything else of Claude's environment
    && printf '%s\n' 'Defaults:claude !lecture, env_reset, always_set_home' \
        'Defaults:claude env_keep += "CLAUDE_CODE_SESSION_ID CLAUDE_CODE_ENTRYPOINT TMUX TMUX_PANE"' \
        'claude ALL=(root) NOPASSWD: /usr/local/bin/svc, /usr/local/bin/tc-scan' > /etc/sudoers.d/tentaclai \
    && chmod 0440 /etc/sudoers.d/tentaclai && visudo -cq
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/start.sh /usr/local/bin/rc-loop /usr/local/bin/cc /usr/local/bin/svc /usr/local/bin/claude-instructions /usr/local/bin/tc-scan /usr/local/bin/tc-statusline /usr/local/bin/tc-connect /usr/local/bin/tc-guard /usr/local/bin/tc-shot \
    # the browser works: Node (both launch paths) and Python render a page
    && tc-shot --selftest \
    && python3 -c 'from playwright.sync_api import sync_playwright as p; b = p().start().chromium.launch(); print("✓ python:", b.version); b.close()' \
    # tmux: mouse scrolling, bigger scrollback, truecolor for Claude's TUI, copies (also Claude's own, OSC 52) reach the browser
    # tab completion in interactive shells (Debian ships it disabled in bash.bashrc)
    && printf '%s\n' '[ -n "$PS1" ] && [ -f /usr/share/bash-completion/bash_completion ] && . /usr/share/bash-completion/bash_completion' >> /etc/bash.bashrc \
    && printf '%s\n' 'set -g mouse on' 'set -g history-limit 50000' 'set -g set-clipboard on' 'set -g allow-passthrough on' \
        'set -g default-terminal "tmux-256color"' 'set -ga terminal-overrides ",*:Tc"' > /etc/tmux.conf

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/start.sh"]
