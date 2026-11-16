import os

STACK_DIR = os.environ.get("STACK_DIR", "/opt/tentaclai")
ENV_FILE = os.path.join(STACK_DIR, ".env")
SERVICES_DIR = os.path.join(STACK_DIR, "services")
SYSTEMS_DIR = os.path.join(STACK_DIR, "systems")
SSH_DIR = os.path.join(STACK_DIR, "ssh")
HOME_DIR = os.path.join(STACK_DIR, "data", "claude")  # Claude's home (user claude in the sandbox)
DATA_DIR = os.environ.get("DATA_DIR", "/data")
CLAUDE_CONTAINER = os.environ.get("CLAUDE_CONTAINER", "tentaclai")
CLAUDE_SERVICE = os.environ.get("CLAUDE_SERVICE", "claude")
# Logs → Containers: key → (container name, what it is)
LOG_CONTAINERS = {
    "tentaclai": (CLAUDE_CONTAINER, "sandbox: Claude Code, svc, Remote Control"),
    "egress": (os.environ.get("EGRESS_CONTAINER", "tentaclai-egress"), "egress gateway: connections, policy"),
    "control": (os.environ.get("CONTROL_CONTAINER", "tentacontrol"), "tentacontrol: this web admin, jobs, notifications"),
}
COMPOSE = ["docker", "compose", "--project-directory", STACK_DIR]

# .env keys that hold secrets: never sent to the browser
SECRET_HINTS = ("TOKEN", "KEY", "PASS", "SECRET", "AUTH", "CREDENTIAL", "PRIVATE", "COOKIE")
SECRET_PARTS = ("PAT",)  # only as a whole name part (NETBIRD_PAT) – not in PATH or PATCHMON_URL


def is_secret(key: str, credentials=()) -> bool:
    """by name, or because a service uses the variable as a credential (credentials: tclib.secret_variables of all)"""
    k = key.upper()
    return key in credentials or any(h in k for h in SECRET_HINTS) or any(p in k.split("_") for p in SECRET_PARTS)


# Structured settings page (everything else shows up under "Weitere Variablen").
# (key, label, help, kind) – kind: text | bool | readonly
SETTINGS_GROUPS = [
    ("General", [
        ("TC_HOSTNAME", "Host name", "how Claude refers to the host tentaclAI runs on", "text"),
        ("TC_DOMAIN", "Internal domain", "suggests the tentacontrol address in ./tentaclai.sh init – service templates use example.com", "text"),
        ("CONTROL_URL", "tentacontrol address", "for the setup link and help, e.g. https://tentacontrol.example.lan", "text"),
        ("TZ", "Time zone", "e.g. Europe/Vienna", "text"),
        ("CLAUDE_CODE_VERSION", "Claude Code version", "latest or a fixed version – applied with the next update", "text"),
        ("CLAUDE_TELEMETRY", "Claude Code telemetry", "off (default): no telemetry, error reports or /bug – API, login and remote control are not affected; applied on the next start", "bool"),
        ("GIT_USER_NAME", "Git name", "default for commits in /workspace – a git service can set its own author", "text"),
        ("GIT_USER_EMAIL", "Git email", "", "text"),
    ]),
    ("Remote control", [
        ("RC_ENABLED", "Remote control enabled", "on/off – applied with “Restart” on the overview", "bool"),
        ("RC_NAME", "Session name", "how the session appears in claude.ai/code and the app", "text"),
        ("RC_WORKDIR", "Start directory", "e.g. /workspace or the stacks directory of a local docker host", "text"),
        ("RC_EXTRA_ARGS", "Extra arguments", "appended to “claude remote-control”", "text"),
        ("RC_RESTART_DELAY", "Restart delay (s)", "wait time before an ended session restarts (default 30)", "text"),
    ]),
    ("Paths & mounts", [
        ("TC_DIR", "Stack directory", "set by ./tentaclai.sh init", "readonly"),
        ("DOCKER_SOCKET", "Docker socket of this host", "only for tentacontrol itself (runs tentaclai); Claude's Docker access comes from docker services", "text"),
        ("HOST_DOCS", "Host documentation", "optional: Markdown file about the host – Claude's instructions point to it, Claude reads it before working on the host", "text"),
        ("CA_CERT", "Own root CA", "optional: PEM file for internal https services", "text"),
    ]),
    ("Approvals", [
        ("APPROVAL_HANDOFF", "Show the approval link in the chat after (s)",
         "a Claude session waits this long for an approval, then svc hands the request back and Claude posts its link in the chat (a running command shows nothing there, e.g. Remote Control in the browser) and waits again for the same request. Default 30, 0 = wait silently", "text"),
    ]),
    ("SSH", [
        ("SSH_CERT_MINUTES", "Certificate lifetime (min)",
         "hosts with login “certificate”: how long each signed certificate is valid, 1–60 (default 5) – needed only to log in", "text"),
    ]),
    ("Jobs", [
        ("JOB_READONLY_HELPERS", "Helpers in read-only jobs",
         "commands besides svc a read-only job may run, comma-separated – text tools only (e.g. head, grep, jq); svc still guards every tentacle. Empty = the defaults (shown greyed out in the field). Shells, interpreters, awk/sed/find/xargs and network or write tools are refused.", "text"),
    ]),
    ("Knowledge", [
        ("KNOWLEDGE_LOCAL_KB", "Site rules budget (KB)",
         "local/CLAUDE.md is read in every request – the Knowledge cleanup job and Claude → Instructions warn above this size (default 6)", "text"),
        ("KNOWLEDGE_NOTES", "Notes per service or system",
         "more notes than this on one service or system count as over budget (default 8)", "text"),
    ]),
    ("Prompt injection", [
        ("INJECTION_GUARD", "Prompt-injection safeguards",
         "on (default): svc marks mail and web pages as untrusted, removes hidden text and flags content that looks like it tries to instruct Claude (warning for Claude, audit log, notification); a hook does the same for WebFetch, WebSearch and MCP tools. A heuristic – it warns, it doesn't block", "bool"),
    ]),
    ("Audit log", [
        ("AUDIT_RETENTION_DAYS", "Keep the audit log (days)",
         "how long archived audit files are kept (default 90)", "text"),
    ]),
    ("Updates", [
        ("UPDATE_CHECK", "Check for new releases", "asks the GitHub API every 6 hours (no token, no data sent) – off: no requests", "bool"),
        ("UPDATE_REPO", "Release repository", "owner/repo whose releases are checked – default mwaldegg/tentaclai (change for a fork)", "text"),
    ]),
    ("Resources", [
        ("CLAUDE_CPUS", "CPU limit", "number of cores for tentaclai", "text"),
        ("CLAUDE_MEMORY", "Memory limit", "e.g. 8g", "text"),
    ]),
]

# .env keys another page (or docker compose itself) manages – listed apart from "Other variables"
# (key or prefix ending in _, where, link)
MANAGED_ELSEWHERE = [
    ("COMPOSE_FILE", "docker compose (set by ./tentaclai.sh init)", None),
    ("EGRESS_MODE", "Network", "/network"),
    ("EGRESS_DIRECT_IP", "Network", "/network"),
    ("NOTIFY_URL_", "Notifications", "/notifications"),
]


def managed_elsewhere(key: str):
    """(where, link) of the page that manages this .env key, or None"""
    for k, where, link in MANAGED_ELSEWHERE:
        if key == k or (k.endswith("_") and key.startswith(k)):
            return where, link
    return None


# read at container start (not by svc) -> claude container must be recreated
RESTART_VARS = {"TZ", "TC_HOSTNAME", "CONTROL_URL", "GIT_USER_NAME", "GIT_USER_EMAIL", "CLAUDE_TELEMETRY",
                "HOST_DOCS", "CA_CERT", "CLAUDE_CPUS", "CLAUDE_MEMORY"}
# RC_* are read by rc-loop on every restart -> "Restart" of remote control is enough
RC_VARS = {"RC_ENABLED", "RC_NAME", "RC_WORKDIR", "RC_EXTRA_ARGS", "RC_RESTART_DELAY"}


def site():
    """non-secret site values for templates/pages"""
    from .envfile import read_env
    env = read_env()
    return {
        "hostname": env.get("TC_HOSTNAME") or "this host",
        "domain": env.get("TC_DOMAIN") or "example.lan",
        "control_url": env.get("CONTROL_URL") or "",
        "tc_dir": env.get("TC_DIR") or STACK_DIR,
        "ca_cert": bool(env.get("CA_CERT")),
    }
