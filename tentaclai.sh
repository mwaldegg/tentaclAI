#!/usr/bin/env bash
# Host helper for tentaclai (sandbox + service gateway for Claude Code) and tentacontrol (web admin).
#   ./tentaclai.sh init       first-time setup: one question (how to reach tentacontrol), then build + start
#                             (--advanced: every question – host, paths, git, remote control, resources; --defaults: none)
#   ./tentaclai.sh            Claude in /workspace (persistent tmux session)
#   ./tentaclai.sh <dir>      Claude in any directory inside the container
#   ./tentaclai.sh rc         attach to the remote-control session
#   ./tentaclai.sh shell      bash in the container as user claude (rootshell: as root – sees the secrets)
#   ./tentaclai.sh login      claude auth login (needed for remote control)
#   ./tentaclai.sh status     container + tmux sessions
#   ./tentaclai.sh svc        apply services/*.json (MCP, repos, catalog) and show status
#   ./tentaclai.sh inventory   guided system inventory → local/CLAUDE.md (Claude asks, you approve)
#   ./tentaclai.sh scan       read-only inventory report (tc-scan)
#   ./tentaclai.sh passwd     reset the tentacontrol admin password and show the username (--username <name>: rename,
#                             --open: emergency access – local sign-in for an hour while only Enterprise sign-in is allowed)
#   ./tentaclai.sh reset-2fa  switch tentacontrol's two-factor sign-in off (lost phone and recovery codes)
#   ./tentaclai.sh setup-url  show the one-time tentacontrol setup link (first start)
#   ./tentaclai.sh update     to the latest release: what's new (changelog) + rebuild + recreate, asks before each step
#                             (--check: only show, --main: latest main instead of the latest release)
# Detach from a tmux session without stopping Claude: Ctrl+B, then D
set -euo pipefail

CONTAINER=tentaclai
STACK_DIR="${TC_STACK_DIR:-$(cd "$(dirname "$(readlink -f "$0")")" && pwd)}"
ENV_FILE="$STACK_DIR/.env"

tclib_name() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]\+/-/g; s/^[-_]*//; s/[-_]*$//' | cut -c1-40; }  # = tclib.service_name_for

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1 | tr -d "'\""; }

set_env() {  # key value – replace or append; a value with other characters than [A-Za-z0-9_./:@+,=-] in single quotes
    local tmp v="$2"
    case "$v" in *"'"*|*$'\n'*|*$'\r'*) echo "tentaclai: $1: a value must not contain ' or line breaks" >&2; return 1 ;; esac
    [[ "$v" =~ ^[A-Za-z0-9_./:@+,=-]*$ ]] || v="'$v'"
    tmp="$(mktemp "$STACK_DIR/.env.XXXX")"
    # the value through ENVIRON, not -v: awk -v reads backslash escapes (\n became a line of its own)
    K="$1" V="$v" awk 'BEGIN{d=0; k=ENVIRON["K"]; v=ENVIRON["V"]} index($0, k"=") == 1 {print k"="v; d=1; next} {print} END{if(!d) print k"="v}' "$ENV_FILE" > "$tmp"
    chmod 600 "$tmp"; mv "$tmp" "$ENV_FILE"
}

INTERACTIVE=1
ask() {  # var "question" default  -> sets var (non-interactive: default)
    local __var="$1" q="$2" def="${3:-}" ans=""
    if [ "$INTERACTIVE" = 1 ]; then
        read -r -p "  $q${def:+ [$def]}: " ans || true
    fi
    printf -v "$__var" '%s' "${ans:-$def}"
}

ask_yn() {  # "question" default(y/n) -> exit code 0 = yes
    local ans="" def="${2:-y}"
    if [ "$INTERACTIVE" = 1 ]; then read -r -p "  $1 [$( [ "$def" = y ] && echo Y/n || echo y/N )]: " ans || true; fi
    ans="${ans:-$def}"; [[ "${ans,,}" == j* || "${ans,,}" == y* ]]
}

ADVANCED=0
adv() {  # ask / ask_yn only with init --advanced – otherwise the default (or the value already in .env)
    local save="$INTERACTIVE"; [ "$ADVANCED" = 1 ] || INTERACTIVE=0
    local rc=0; "$@" || rc=$?
    INTERACTIVE="$save"; return "$rc"
}

ask_choice() {  # var "question" default option...  (options "key|Text")
    local __var="$1" q="$2" def="$3"; shift 3
    if [ "$INTERACTIVE" = 1 ]; then
        echo "  $q"
        local o; for o in "$@"; do echo "    [${o%%|*}] ${o#*|}"; done
    fi
    ask "$__var" "Choice" "$def"
}

cmd_init() {
    cd "$STACK_DIR"
    [ "${1:-}" = "--advanced" ] && ADVANCED=1
    [ "${1:-}" = "--defaults" ] || [ ! -t 0 ] && INTERACTIVE=0
    local note=""
    if [ "$INTERACTIVE" = 0 ]; then note=" (no questions)"
    elif [ "$ADVANCED" = 0 ]; then note=" – everything else has defaults (change them in Settings, or run init --advanced)"; fi
    echo "🐙 tentaclai – first-time setup$note"
    if [ ! -f .env ]; then install -m 600 .env.example .env; echo "→ created .env from .env.example"; fi
    chmod 600 .env
    cur() { local v; v="$(env_value "$1")"; echo "${v:-$2}"; }

    echo; echo "1/5 Host & paths"
    set_env TC_DIR "$STACK_DIR"
    adv ask v "Name of this host (how Claude refers to it)" "$(cur TC_HOSTNAME "$(hostname -s)")";     set_env TC_HOSTNAME "$v"
    adv ask v "Internal domain (for service templates)" "$(cur TC_DOMAIN example.lan)";              set_env TC_DOMAIN "$v"
    local tz; tz="$(cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
    adv ask v "Time zone" "$(cur TZ "$tz")";                                                       set_env TZ "$v"
    adv ask v "Docker socket of this host (for tentacontrol)" "$(cur DOCKER_SOCKET /var/run/docker.sock)"; set_env DOCKER_SOCKET "$v"
    adv ask v "Host docs for Claude (markdown file, empty = none)" "$(cur HOST_DOCS '')";        set_env HOST_DOCS "$v"
    adv ask v "Custom root CA (PEM, empty = none)" "$(cur CA_CERT '')";                           set_env CA_CERT "$v"

    echo; echo "2/5 Access to tentacontrol"
    local mode host url
    ask_choice mode "How should the web UI be reachable?" 2 \
        "1|only on this host (127.0.0.1:8484, e.g. via SSH tunnel)" \
        "2|in the LAN on port 8484 – keep it off the internet" "3|via nginx-proxy (VIRTUAL_HOST)" "4|via Traefik"
    case "$mode" in
        2) adv ask v "Port" "$(cur CONTROL_PORT 8484)"; set_env CONTROL_BIND 0.0.0.0; set_env CONTROL_PORT "$v"
           url="http://$(hostname -I 2>/dev/null | awk '{print $1}'):$v" ;;
        3|4) ask host "Hostname" "tentacontrol.$(env_value TC_DOMAIN)"; url="https://$host"
           if [ -f compose.override.yaml ]; then echo "  compose.override.yaml exists – not overwritten, please add it yourself"
           elif [ "$mode" = 3 ]; then
               printf 'services:\n  control:\n    environment:\n      VIRTUAL_HOST: %s\n      VIRTUAL_PORT: "8080"\n    ports: !reset []\n' "$host" > compose.override.yaml
               echo "  → created compose.override.yaml for nginx-proxy"
           else
               ask net "Name of the Traefik network" "proxy"
               printf 'services:\n  control:\n    labels:\n      traefik.enable: "true"\n      traefik.http.routers.tentacontrol.rule: Host(`%s`)\n      traefik.http.services.tentacontrol.loadbalancer.server.port: "8080"\n    networks: [default, %s]\n    ports: !reset []\nnetworks:\n  %s:\n    external: true\n' "$host" "$net" "$net" > compose.override.yaml
               echo "  → created compose.override.yaml for Traefik"
           fi ;;
        *) set_env CONTROL_BIND 127.0.0.1; set_env CONTROL_PORT 8484; url="http://127.0.0.1:8484" ;;
    esac
    # the chosen access mode wins over an old value
    [ "$INTERACTIVE" = 0 ] && [ -n "$(env_value CONTROL_URL)" ] && url="$(env_value CONTROL_URL)"
    adv ask v "URL of tentacontrol" "$url"; set_env CONTROL_URL "$v"

    echo; echo "3/5 Claude"
    adv ask v "Git name for commits" "$(cur GIT_USER_NAME '')";           set_env GIT_USER_NAME "$v"
    adv ask v "Git email" "$(cur GIT_USER_EMAIL '')";                    set_env GIT_USER_EMAIL "$v"
    adv ask v "Claude Code version" "$(cur CLAUDE_CODE_VERSION latest)";  set_env CLAUDE_CODE_VERSION "$v"
    if adv ask_yn "Enable remote control (claude.ai/code + app)?" y; then
        set_env RC_ENABLED true
        adv ask v "Name of the remote session" "$(cur RC_NAME "$(env_value TC_HOSTNAME)")"; set_env RC_NAME "$v"
    else set_env RC_ENABLED false; fi

    echo; echo "4/5 Resources"
    local cpus; cpus="$(nproc 2>/dev/null || echo 4)"; [ "$cpus" -gt 4 ] && cpus=4
    adv ask v "CPU limit (cores)" "$(cur CLAUDE_CPUS "$cpus")";   set_env CLAUDE_CPUS "$v"
    adv ask v "Memory limit" "$(cur CLAUDE_MEMORY 8g)";               set_env CLAUDE_MEMORY "$v"

    echo; echo "5/5 Files"
    mkdir -p data/home data/control workspace local services ssh/config.d ssh/keys
    chmod 700 data/control ssh ssh/keys
    [ -f ssh/known_hosts ] || install -m 600 /dev/null ssh/known_hosts
    if [ ! -f ssh/keys/tentaclai_ed25519 ]; then
        ssh-keygen -q -t ed25519 -N '' -C "tentaclai@$(env_value TC_HOSTNAME)" -f ssh/keys/tentaclai_ed25519
        echo "  → generated SSH key ssh/keys/tentaclai_ed25519"
    fi
    [ -f local/CLAUDE.md ] || { cp local/CLAUDE.example.md local/CLAUDE.md 2>/dev/null || printf '# Site rules for Claude\n' > local/CLAUDE.md; echo "  → created local/CLAUDE.md"; }
    [ -f compose.override.yaml ] || printf '# site additions (see compose.override.example.yaml)\nservices: {}\n' > compose.override.yaml

    set_env COMPOSE_FILE "compose.yaml:compose.override.yaml"
    docker compose config --quiet && echo "  ✓ configuration valid"

    echo
    if ask_yn "Build and start everything now (a few minutes)?" y && [ "$INTERACTIVE" = 1 ]; then
        docker compose up -d --build control
        for _ in $(seq 1 30); do docker logs tentacontrol 2>&1 | grep -q 'setup?token=' && break; sleep 1; done
        echo; echo "Setup link (one-time) – open it now to set your password while the sandbox builds:"; "$0" setup-url
        echo; echo "Building the sandbox …"
        docker compose up -d --build
        echo
        echo "Next, in tentacontrol:"
        echo "  1. Overview → Sign in now        – claude auth login with your claude.ai account"
        echo "  2. Tentacles → SSH hosts → Add host → \"This host\" – Docker on this machine, ready to use"
        echo "  3. Ask Claude: svc docker $(tclib_name "$(env_value TC_HOSTNAME)") ps"
    else
        echo "Next: docker compose up -d --build && ./tentaclai.sh setup-url"
    fi
}

cmd_update() {  # git pull + changelog of the new versions + rebuild + recreate – asks before every step
    if [ -z "${TC_UPDATE_COPY:-}" ]; then
        # git pull may replace this very script – continue from a temporary copy
        local copy; copy="$(mktemp)"; cp "$0" "$copy"
        TC_UPDATE_COPY="$copy" TC_STACK_DIR="$STACK_DIR" exec bash "$copy" update "$@"
    fi
    trap 'rm -f "$TC_UPDATE_COPY"' EXIT
    cd "$STACK_DIR"
    [ -d .git ] && command -v git >/dev/null || { echo "$STACK_DIR is no git checkout (or git is missing) – update by hand"; exit 1; }
    local old new branch upstream behind target mode="${1:-}"
    old="$(cat VERSION 2>/dev/null || echo "?")"
    echo "🐙 tentaclAI – installed v$old"
    git fetch --quiet --tags origin || { echo "✗ git fetch failed"; exit 1; }
    branch="$(git rev-parse --abbrev-ref HEAD)"
    upstream="$(git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>/dev/null)" || { echo "✗ branch $branch has no upstream"; exit 1; }
    if [ "$mode" = "--main" ]; then
        target="$upstream"   # everything on main, released or not
    else
        target="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"
        [ -n "$target" ] || { echo "✗ no release tags found – use --main"; exit 1; }
        if ! git merge-base --is-ancestor HEAD "$target"; then
            echo "✓ already at or past the latest release $target (use --main for unreleased changes)"; return 0
        fi
    fi
    behind="$(git rev-list --count "HEAD..$target")"
    if [ "$behind" = 0 ]; then echo "✓ up to date ($target)"; return 0; fi
    new="$(git show "$target:VERSION" 2>/dev/null || echo "?")"
    echo "→ $behind new commit(s) up to $target – version v$new"
    echo; echo "What's new (CHANGELOG – read the Upgrade steps):"; echo
    # every changelog section newer than the installed version
    git show "$target:CHANGELOG.md" | awk -v old="v$old" '/^## /{ if (index($0, old " ") || $0 ~ ("## " old "$")) exit; p=1 } p' | sed 's/^/   /'
    [ "$mode" = "--check" ] && return 0
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "✗ tracked files have local changes – commit or stash them first:"; git status --short --untracked-files=no; exit 1
    fi
    ask_yn "Pull and rebuild the images now?" y || return 0
    git merge --ff-only --quiet "$target" || { echo "✗ can't fast-forward to $target – local commits on $branch?"; exit 1; }
    docker compose build
    echo
    if ask_yn "Recreate tentacontrol now (the web admin restarts briefly)?" y; then
        docker compose up -d --no-deps control
    fi
    docker compose up -d --no-deps egress   # the sandbox's way out – cuts open connections only when it changed
    if ask_yn "Recreate tentaclai now? Running Claude sessions and Remote Control end." n; then
        docker compose up -d --no-deps --force-recreate claude
    else
        echo "  later: docker compose up -d --force-recreate claude   (or Overview → Apply now)"
    fi
    echo "✓ updated to v$(cat VERSION 2>/dev/null || echo "?") – check the upgrade steps above for anything else"
}

case "${1:-}" in
    init)      cmd_init "${2:-}"; exit 0 ;;
    passwd)    shift; exec docker exec -it tentacontrol tentacontrol-passwd "$@" ;;
    reset-2fa) exec docker exec -it tentacontrol tentacontrol-passwd --reset-2fa ;;
    setup-url)
        url="$(env_value CONTROL_URL)"
        docker logs tentacontrol 2>&1 | grep -E 'setup\?token=' | tail -1 | sed "s|https://<host>|${url:-http://127.0.0.1:8484}|"
        exit 0 ;;
    update)    cmd_update "${2:-}"; exit 0 ;;
    -h|--help|help) awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "$0"; exit 0 ;;  # the comment block above
esac

if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]; then
    echo "Container $CONTAINER is not running – starting it …"
    docker compose --project-directory "$STACK_DIR" up -d claude
fi

case "${1:-}" in
    "")       exec docker exec -it -u claude "$CONTAINER" cc ;;
    login)    exec docker exec -it -u claude "$CONTAINER" claude auth login ;;
    rc)       exec docker exec -it -u claude "$CONTAINER" cc rc ;;
    inventory) exec docker exec -it -u claude "$CONTAINER" tmux new-session -A -s claude-inventory -c /workspace claude /inventory ;;
    scan)     exec docker exec "$CONTAINER" tc-scan ;;
    shell)    exec docker exec -it -u claude "$CONTAINER" bash ;;
    rootshell) exec docker exec -it "$CONTAINER" bash ;;
    status)
        docker ps --filter "name=^${CONTAINER}$" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
        echo; docker exec -u claude "$CONTAINER" tmux ls 2>/dev/null || echo "no tmux sessions" ;;
    svc|mcp)
        docker exec "$CONTAINER" svc sync
        echo; docker exec "$CONTAINER" svc list
        echo; docker exec -u claude "$CONTAINER" claude mcp list ;;
    *)        exec docker exec -it -u claude "$CONTAINER" cc "$1" ;;
esac
