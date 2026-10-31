#!/usr/bin/env bash
# Runs as root on every container start: protects the secrets, prepares Claude's home and the services,
# then starts CMD as the unprivileged user "claude".
#   root   – .env, SSH keys, service files, svc state (/root = data/home)
#   claude – Claude Code, /home/claude (= data/claude), /workspace; reaches services only via `sudo svc`
set -euo pipefail

TC_DIR="${TC_DIR:-/opt/tentaclai}"
as_claude() { setpriv --reuid=claude --regid=claude --init-groups env -i HOME=/home/claude USER=claude LOGNAME=claude \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG="${LANG:-C.UTF-8}" "$@"; }
envval() {  # a value from the stack's .env (root only reads it)
    python3 -c 'import os, sys; sys.path.insert(0, "/usr/local/lib/tentaclai"); import tclib
print(tclib.read_env(os.path.join(sys.argv[1], ".env")).get(sys.argv[2], ""))' "$TC_DIR" "$1"
}

# Optional own root CA (CA_CERT in .env, mounted as /etc/tentaclai/ca.crt; /dev/null = none).
# Added to the system bundle; Node uses it via NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
if [ -s /etc/tentaclai/ca.crt ]; then
    cp /etc/tentaclai/ca.crt /usr/local/share/ca-certificates/tentaclai-site-ca.crt
    update-ca-certificates >/dev/null 2>&1 || true
fi

# svc runs through sudo with a reset environment – it finds the stack and the egress gateway here
echo "$TC_DIR" > /etc/tentaclai/tc-dir
echo "${HTTPS_PROXY:-}" > /etc/tentaclai/proxy
chmod 644 /etc/tentaclai/tc-dir /etc/tentaclai/proxy

# Secrets: root only (also fixes installations from before the privilege separation)
chmod 600 "$TC_DIR"/.env "$TC_DIR"/.env.* 2>/dev/null || true
chmod 700 /root "$TC_DIR/data/control" 2>/dev/null || true
# ssh refuses a config owned by another user (e.g. a clone made as a normal user) – the ssh dir belongs to root
chown -R root:root /root/.ssh 2>/dev/null || true
chmod 700 /root/.ssh /root/.ssh/keys 2>/dev/null || true
chmod 600 /root/.ssh/config /root/.ssh/keys/*_ed25519 2>/dev/null || true

# everything in Claude's areas belongs to Claude (no symlinks followed)
find /home/claude /workspace -xdev ! -user claude -exec chown -h claude:claude {} + 2>/dev/null || true
chmod 700 /home/claude

umask 077
# git: root only ever works on its own mirrors – it must not trust repositories owned by others
git config --global --unset-all safe.directory 2>/dev/null || true
name="$(envval GIT_USER_NAME)"; mail="$(envval GIT_USER_EMAIL)"
[ -n "$name" ] && as_claude git config --global user.name "$name"
[ -n "$mail" ] && as_claude git config --global user.email "$mail"
as_claude git config --global init.defaultBranch main

# SSH: /root/.ssh is the stack's ssh/ dir (config, config.d/, keys/, known_hosts) – used by svc only
if [ ! -f /root/.ssh/keys/tentaclai_ed25519 ] && [ -d /root/.ssh ]; then
    mkdir -p /root/.ssh/keys
    ssh-keygen -q -t ed25519 -N '' -C "tentaclai@$(envval TC_HOSTNAME | grep . || echo tentaclai)" -f /root/.ssh/keys/tentaclai_ed25519
fi

# Claude's user-level instructions and the slash commands shipped with the image (own commands stay untouched)
as_claude mkdir -p /home/claude/.claude/commands
# the site rules are imported by Claude (@…) – an unreadable file is skipped without a word
if [ -f "$TC_DIR/local/CLAUDE.md" ]; then chmod 644 "$TC_DIR/local/CLAUDE.md"; fi
claude-instructions | as_claude sh -c 'cat > /home/claude/.claude/CLAUDE.md' || echo "could not generate CLAUDE.md"
as_claude sh -c 'cp -f /etc/tentaclai/commands/*.md /home/claude/.claude/commands/' 2>/dev/null || true
# status line (caged octopus + pending approvals) – only if the user has none of their own;
# telemetry, error reports and /bug off unless CLAUDE_TELEMETRY=true in .env
TRAFFIC_OFF="$( [ "$(envval CLAUDE_TELEMETRY | tr A-Z a-z)" = "true" ] || echo 1 )"
# skill modes and models from tentacontrol → Settings → Skills / Models (root-only data dir; Claude gets just the result)
ctrl_state() {  # <file> <tclib function>
    python3 -c 'import json, sys; sys.path.insert(0, "/usr/local/lib/tentaclai"); import tclib
try:
    s = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    s = {}
print(json.dumps(getattr(tclib, sys.argv[2])(s)))' "$TC_DIR/data/control/$1" "$2" 2>/dev/null || echo '{}'
}
SKILLS="$(ctrl_state skills.json skill_overrides)"
MODELS="$(ctrl_state models.json models)"
as_claude env TRAFFIC_OFF="$TRAFFIC_OFF" SKILLS="$SKILLS" MODELS="$MODELS" python3 - <<'PY' || echo "could not set Claude's settings"
import json, os, sys
sys.path.insert(0, "/usr/local/lib/tentaclai")
import tclib
p = "/home/claude/.claude/settings.json"
try:
    s = json.load(open(p))
except (OSError, ValueError):
    s = {}
cur = s.get("statusLine") or {}
if not cur or cur.get("command") == "tc-statusline":
    s["statusLine"] = {"type": "command", "command": "tc-statusline", "padding": 0, "refreshInterval": 5}
env = s.setdefault("env", {})
# single switches – CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC would also stop the feature flags remote control needs
env.pop("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", None)
for k in ("DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "DISABLE_BUG_COMMAND"):
    if os.environ.get("TRAFFIC_OFF"):
        env[k] = "1"
    else:
        env.pop(k, None)
if not env:
    s.pop("env")
tclib.apply_skill_overrides(s, json.loads(os.environ.get("SKILLS") or "{}"))
m = tclib.models(json.loads(os.environ.get("MODELS") or "{}"))
tclib.apply_models(s, m)
open(p + ".tmp", "w").write(json.dumps(s, indent=2) + "\n")
os.replace(p + ".tmp", p)
tclib.write_model_commands(m)  # after the plain copy above: /inventory and /onboard with their model
PY

# root-owned managed settings: claude.ai connectors switched off in tentacontrol (default: all) and the tc-guard hook
python3 - "$TC_DIR/data/control/connectors.json" "$TC_DIR/.env" <<'PY' || true
import json, os, sys
sys.path.insert(0, "/usr/local/lib/tentaclai")
import tclib
try:
    known = json.load(open(sys.argv[1])).get("known", {})
except (OSError, ValueError):
    known = {}
os.makedirs("/etc/claude-code", exist_ok=True)
os.chmod("/etc/claude-code", 0o755)  # umask 077 above – Claude must be able to read its policy, or it is silently ignored
settings = tclib.managed_settings([n for n, c in known.items() if not c.get("enabled")], tclib.guard_on(tclib.read_env(sys.argv[2])))
with open("/etc/claude-code/managed-settings.json", "w") as f:
    json.dump(settings, f, indent=1)
os.chmod("/etc/claude-code/managed-settings.json", 0o644)
PY

# Services (services/*.json): MCP -> Claude config, clone missing repos, regenerate /workspace/SERVICES.md
echo "svc sync:"
svc sync || echo "svc sync failed – container starts anyway"

# CMD as Claude, with a clean environment
exec setpriv --reuid=claude --regid=claude --init-groups env -i HOME=/home/claude USER=claude LOGNAME=claude SHELL=/bin/bash \
    PATH="$PATH" LANG="${LANG:-C.UTF-8}" LC_ALL="${LC_ALL:-C.UTF-8}" TERM="${TERM:-xterm-256color}" TZ="${TZ:-UTC}" \
    TC_DIR="$TC_DIR" NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-}" DISABLE_AUTOUPDATER="${DISABLE_AUTOUPDATER:-1}" \
    PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-}" PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD="${PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD:-}" \
    NODE_PATH="${NODE_PATH:-}" COREPACK_ENABLE_DOWNLOAD_PROMPT="${COREPACK_ENABLE_DOWNLOAD_PROMPT:-0}" \
    HTTP_PROXY="${HTTP_PROXY:-}" HTTPS_PROXY="${HTTPS_PROXY:-}" NO_PROXY="${NO_PROXY:-}" \
    http_proxy="${HTTP_PROXY:-}" https_proxy="${HTTPS_PROXY:-}" no_proxy="${NO_PROXY:-}" "$@"
