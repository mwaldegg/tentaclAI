"""tclib – logic shared by the tentaclAI sandbox tools (svc, tc-scan, claude-instructions) and tentacontrol.

One implementation for: .env files, ${VAR} placeholders, services and systems, and SSH hosts in ssh/config.d.
Standard library only – it is copied into both images.
"""
import glob
import json
import os
import re
import time

# ---------------------------------------------------------------- .env and ${VAR}

VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def read_env(path):
    """KEY=value lines of a compose .env file (comments and quotes handled); {} if missing"""
    values = {}
    try:
        with open(path) as f:
            for line in f:
                m = ENV_LINE.match(line)
                if m:
                    values[m.group(1)] = unquote(m.group(2))
    except OSError:
        pass
    return values


def variables(obj):
    """all ${VAR} names used in a (nested) value; keys starting with _ are ignored"""
    found = set()
    if isinstance(obj, str):
        found.update(VAR.findall(obj))
    elif isinstance(obj, list):
        for v in obj:
            found |= variables(v)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not k.startswith("_"):
                found |= variables(v)
    return found


def render(obj, env, keep_unknown=False):
    """replace ${VAR} with values from env; unknown ones become '' (or stay as they are with keep_unknown)"""
    if isinstance(obj, str):
        return VAR.sub(lambda m: env.get(m.group(1)) or (m.group(0) if keep_unknown else ""), obj)
    if isinstance(obj, list):
        return [render(v, env, keep_unknown) for v in obj]
    if isinstance(obj, dict):
        return {k: render(v, env, keep_unknown) for k, v in obj.items() if not k.startswith("_")}
    return obj


_CREDENTIAL_KEYS = ("auth", "headers", "env")      # everything below them is a credential …
_NOT_CREDENTIAL = ("type", "user", "username", "login", "header", "param", "client_id", "url", "base_url", "token_url")
_CREDENTIAL_WORDS = ("password", "token", "secret")  # … and fields named like this anywhere


def secret_variables(obj, inside=False):
    """${VAR}s a service uses as credentials – the UI never shows their values, whatever the variable is called
    (e.g. NETBIRD_PAT). User names, header names and URLs stay visible."""
    found = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key.startswith("_"):
                continue
            here = key not in _NOT_CREDENTIAL and (inside or key in _CREDENTIAL_KEYS or any(w in key for w in _CREDENTIAL_WORDS))
            found |= secret_variables(v, here)
    elif isinstance(obj, list):
        for v in obj:
            found |= secret_variables(v, inside)
    elif isinstance(obj, str) and inside:
        found.update(VAR.findall(obj))
    return found


_SECRET_HEADER = ("auth", "key", "token", "secret", "password", "cookie")  # headers/env entries that hold a credential


def literal_secrets(obj, inside=False, path=()):
    """key paths (tuples) where a credential position holds a plain value instead of a ${VAR} – such a value would
    leave the installation with an export or a template. Other headers/env entries (e.g. Accept) are not counted."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key.startswith("_") or key in _NOT_CREDENTIAL:
                continue
            if key in ("headers", "env") and isinstance(v, dict):
                for hk, hv in v.items():
                    if any(w in str(hk).lower() for w in _SECRET_HEADER):
                        found += literal_secrets(hv, True, path + (k, hk))
                continue
            found += literal_secrets(v, inside or key == "auth" or any(w in key for w in _CREDENTIAL_WORDS), path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += literal_secrets(v, inside, path + (i,))
    elif isinstance(obj, str) and inside and obj.strip() and not VAR.search(obj):
        found.append(path)
    return found


def missing(obj, env):
    return sorted(v for v in variables(obj) if not env.get(v))


# ---------------------------------------------------------------- services and systems

PARTS = ("api", "mcp", "git", "docker", "db", "web", "files", "smtp", "imap")


def _load_dir(path, errors=None):
    """name -> parsed JSON of <path>/*.json (files starting with _ are templates/examples)"""
    items = {}
    for p in sorted(glob.glob(os.path.join(path, "*.json"))):
        base = os.path.basename(p)
        if base.startswith("_"):
            continue
        try:
            with open(p) as f:
                data = json.load(f)
        except ValueError as e:
            if errors is not None:
                errors[base[:-5]] = str(e)
            continue
        data.setdefault("name", base[:-5])
        items[base[:-5]] = data
    return items


def load_systems(stack_dir, errors=None):
    return _load_dir(os.path.join(stack_dir, "systems"), errors)


def load_services(services_dir, systems=None, errors=None):
    """services by name; with systems given, docker (mode ssh) and files parts inherit the system's SSH host"""
    services = _load_dir(services_dir, errors)
    for svc in services.values():
        sysd = (systems or {}).get(svc.get("system", ""))
        if not sysd or not sysd.get("ssh_host"):
            continue
        d, f = svc.get("docker"), svc.get("files")
        if d and d.get("mode", "ssh") == "ssh" and not d.get("ssh_host"):
            d["ssh_host"] = sysd["ssh_host"]
        if f and not f.get("ssh_host"):
            f["ssh_host"] = sysd["ssh_host"]
    return services


TLS_PARTS = ("api", "mcp", "git", "db", "web", "smtp", "imap")
# mail parts: security → default port
MAIL_PORTS = {"smtp": {"starttls": 587, "ssl": 465, "none": 25}, "imap": {"ssl": 993, "starttls": 143, "none": 143}}


# ---------------------------------------------------------------- scheduled jobs (tentacontrol runs them, svc shows them)

DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def schedule_text(sched):
    """a job's schedule in words"""
    k = (sched or {}).get("kind")
    if k == "manual":
        return "manual"
    if k == "hourly":
        return f"every hour at :{int(sched.get('minute', 0)):02d}"
    if k == "daily":
        return f"daily at {sched['time']}"
    if k == "weekly":
        return f"every {DAYS[int(sched['day'])]} at {sched['time']}"
    if k == "every":
        return f"every {sched['hours']} h"
    if k == "cron":
        return f"cron {sched['expr']}"
    return "?"


MAIL_ADDRESS = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def mail_addresses(svc, env):
    """the addresses a mail service stands for, primary first: the imap/smtp login where it is an address, then smtp.from"""
    found = [render(str((svc.get(part) or {}).get(key, "")), env, keep_unknown=True)
             for part, key in (("imap", "user"), ("smtp", "user"), ("smtp", "from"))]
    return list(dict.fromkeys(a for a in found if MAIL_ADDRESS.match(a)))


def mail_address(svc, env):
    """the mailbox a mail service stands for – its first address, '' if it has none"""
    return (mail_addresses(svc, env) or [""])[0]


def mail_port(part, cfg):
    """port of an smtp/imap part – given, or the default of its security (smtp: starttls, imap: ssl)"""
    sec = cfg.get("security") or ("starttls" if part == "smtp" else "ssl")
    return int(cfg.get("port") or MAIL_PORTS[part].get(sec, MAIL_PORTS[part]["none"]))


def tls_unverified(svc):
    """parts whose TLS certificates are not verified (insecure_tls: true)"""
    return [p for p in TLS_PARTS if isinstance(svc.get(p), dict) and svc[p].get("insecure_tls")]


def kinds(svc):
    return [k for k in PARTS if k in svc]


def enabled(svc):
    return svc.get("enabled", True) is not False


def status(svc, env):
    """(state, missing vars): state is 'disabled', 'missing' or 'active'"""
    if not enabled(svc):
        return "disabled", []
    miss = sorted(set().union(*[set(missing(svc.get(p, {}), env)) for p in PARTS]))
    return ("missing", miss) if miss else ("active", [])


def status_text(svc, env):
    state, miss = status(svc, env)
    return "missing: " + ", ".join(miss) if state == "missing" else state


def _url_host(url):
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?", url or "", re.I)
    if not m:
        return None
    default = {"https": 443, "http": 80, "ssh": 22}.get(url.split(":", 1)[0].lower())
    return m.group(1).strip("[]").lower(), int(m.group(2)) if m.group(2) else default


def reach_hosts(services, env, ssh_hosts_list=()):
    """(host, port) → name of the reach (a tentacle: service or SSH host) for every active service part and SSH host;
    port None = any port. Used by the egress gateway (auto-allow) and tentacontrol (origin of a destination)."""
    out = {}
    for name, svc in services.items():
        if not enabled(svc) or missing(svc, env):
            continue
        r = render(svc, env)
        for part, key in (("api", "base_url"), ("mcp", "url"), ("web", "base_url"), ("git", "url")):
            hp = _url_host((r.get(part) or {}).get(key, ""))
            if hp:
                out.setdefault(hp, name)
        g = (r.get("git") or {}).get("url", "")
        m = re.match(r"^(?:[^@/]+@)?([^:/]+):", g)  # scp-like git@host:path
        if m and "://" not in g:
            out.setdefault((m.group(1).lower(), 22), name)
        for part in ("smtp", "imap"):
            m = r.get(part) or {}
            if m.get("host"):
                out.setdefault((str(m["host"]).lower(), mail_port(part, m)), name)
        db = r.get("db") or {}
        if db.get("host"):
            out.setdefault((str(db["host"]).lower(), int(db.get("port") or (3306 if str(db.get("engine", "")).lower() in ("mysql", "mariadb") else 5432))), name)
    for h in ssh_hosts_list:
        if h.get("hostname"):
            out.setdefault((h["hostname"].lower(), int(h.get("port") or 22)), f"ssh {h['alias']}")
    return out


def egress_patterns(text):
    """patterns from an allow/block list (comments and blank lines ignored)"""
    return [l.split("#", 1)[0].strip().lower() for l in text.splitlines() if l.split("#", 1)[0].strip()]


def is_ip(s):
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def egress_match(pattern, host, port, ips=()):
    """pattern: host, *.domain, IP or CIDR (e.g. 10.0.0.0/8), each optionally with :port (no port = any port).
    Names match the requested host; IPs and CIDRs match the host when it is an address, and every resolved address."""
    import ipaddress
    p_host, _, p_port = pattern.rpartition(":") if pattern.count(":") == 1 else (pattern, "", "")
    p_host = p_host or pattern
    if p_port and p_port != str(port):
        return False
    host = host.lower().rstrip(".")
    if "/" in p_host or is_ip(p_host):
        try:
            net = ipaddress.ip_network(p_host, strict=False)
        except ValueError:
            return False
        addrs = ([host] if is_ip(host) else []) + list(ips)
        return any(ipaddress.ip_address(a) in net for a in addrs if is_ip(a))
    if p_host.startswith("*."):
        return host.endswith(p_host[1:])
    return host == p_host


def egress_rule(host, port, ips=(), default=(), block=(), allow=(), tentacles=None, grants=None, now=None):
    """(kind, label) of the rule that covers a destination – one order for the gateway and tentacontrol's Network page:
    built-in list (never blockable) → blocklist → own allowlist → tentacles → grants. kind "unknown" = no rule.
    Names match as requested; IP/CIDR rules also match the resolved addresses ips."""
    if any(egress_match(p, host, port) for p in default):
        return "default", "built-in"
    if any(egress_match(p, host, port, ips) for p in block):
        return "blocked", "blocklist"
    if any(egress_match(p, host, port, ips) for p in allow):
        return "allow", "own allowlist"
    name = (tentacles or {}).get((host, port)) or (tentacles or {}).get((host, None))
    if name:
        return "tentacle", name
    if (grants or {}).get(f"{host}:{port}", 0) > (now or time.time()):
        return "grant", "approved for a while"
    return "unknown", ""


# ---------------------------------------------------------------- access modes

ACCESS = ("read", "write", "confirm")
ACCESS_ALIASES = {"ro": "read", "rw": "write"}  # the names before v0.16 – still understood, no longer written
ACCESS_NAMES = ACCESS + tuple(ACCESS_ALIASES)


def access(value, default="read"):
    """normalise an access mode (ro → read, rw → write); an unknown value is read – the safe side"""
    mode = str(default if value in (None, "") else value).strip().lower()
    mode = ACCESS_ALIASES.get(mode, mode)
    return mode if mode in ACCESS else "read"


def git_author(git):
    """the commit author a git part sets for its working copy – (name, email), or None without both"""
    author = git.get("author") if isinstance(git.get("author"), dict) else {}
    return (str(author["name"]), str(author["email"])) if author.get("name") and author.get("email") else None


def part_default(part):
    """the access a service part has without an explicit one: smtp asks, api writes, everything else reads"""
    return {"smtp": "confirm", "api": "write"}.get(part, "read")


def migrate_access(data):
    """rewrite ro/rw in a service's parts to read/write – returns True if something changed"""
    changed = False
    for p in PARTS:
        d = data.get(p)
        if isinstance(d, dict) and str(d.get("access", "")).strip().lower() in ACCESS_ALIASES:
            d["access"] = ACCESS_ALIASES[str(d["access"]).strip().lower()]
            changed = True
    return changed


# ---------------------------------------------------------------- SSH hosts (ssh/config.d/*.conf)

META = re.compile(r"^\s*#\s*tentaclai:\s*(sudo|access)\s*=\s*(.*?)\s*$")
SSH_ACCESS_DEFAULT = "confirm"


# ---- risk of a write (approvals): what makes a single action dangerous – shown in red, never covered by a grant
_RISK_DOCKER = (
    (r"(^|\s)--privileged\b", "privileged container – full access to the host"),
    (r"(^|\s)(-v|--volume)[ =]/:|(^|\s)--mount[ =]\S*(src|source)=/(,|\s|$)", "mounts the host's root file system"),
    (r"(^|\s)(-v|--volume|--mount)[ =]\S*docker\.sock", "mounts the Docker socket – control of the host"),
    (r"(^|\s)--(pid|network|net|ipc|uts|userns)[ =]host\b", "shares a host namespace"),
    (r"(^|\s)--cap-add\b", "adds kernel capabilities"),
    (r"^docker (rm|rmi|kill)\b|^docker (container|image|volume|network) (rm|remove|prune)\b", "deletes"),
    (r"^docker (system|volume|image|container|network|builder) prune\b", "prunes"),
    (r"^docker exec\b", "runs a command inside a container"),
    (r"^compose \S+ down\b.*\s(-v|--volumes)\b", "removes the stack with its volumes – data is lost"),
    (r"^compose \S+ down\b", "stops and removes the stack"),
    (r"^compose \S+ (exec|run)\b", "runs a command inside a container"),
)
_RISK_SHELL = (
    (r"\brm\s+(-\w*[rf]\w*\s+)+", "deletes files recursively or forced"),
    (r"\b(mkfs|fdisk|parted|wipefs|dd)\b", "writes to disks"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "shuts down or reboots the host"),
    (r"\bsystemctl\s+(stop|restart|disable|mask|kill)\b", "stops or restarts a system service"),
    (r"\b(iptables|nft|ufw)\b", "changes the firewall"),
    (r"\b(chmod|chown)\s+-\w*R", "changes permissions recursively"),
    (r"\b(userdel|passwd|usermod)\b|authorized_keys", "changes accounts or SSH keys"),
    (r">\s*/(etc|boot|dev)/", "overwrites a system file"),
    (r"\bcurl\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\bwget\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b", "runs a script from the internet"),
)
_RISK_SQL = (
    (r"\b(drop|truncate)\s+(table|database|schema)\b|\btruncate\b", "drops or empties tables"),
    (r"\b(delete\s+from|update)\s+(?:(?!\bwhere\b).)*$", "changes every row (no WHERE)"),
    (r"\balter\s+(table|database|user|role)\b", "changes the schema or a role"),
    (r"\b(grant|revoke)\b", "changes permissions"),
)


def write_risks(part, action):
    """the reasons a write is dangerous (empty: an ordinary write) – a hint for the approver, matched on svc's action
    text ("docker …", "compose <stack> …", "ssh …", "SQL: …", "push …", "DELETE /path")"""
    a = str(action or "").strip()
    found = []

    def scan(rules, text, flags=0):
        for pat, why in rules:
            if re.search(pat, text, flags) and why not in found:
                found.append(why)
    if part == "docker":
        scan(_RISK_DOCKER, a)
        if a.startswith("compose ") and " down" in a and "removes the stack with its volumes – data is lost" in found:
            found.remove("stops and removes the stack")
    elif part == "ssh":
        if a == "ssh (interactive shell)":
            found.append("interactive shell – every command runs without a further approval")
        scan(_RISK_SHELL, a)
    elif part == "db":
        if a == "interactive SQL shell":
            found.append("interactive SQL shell – every statement runs without a further approval")
        scan(_RISK_SQL, a[5:] if a.startswith("SQL: ") else a, re.I | re.S)
    elif part == "git" and re.search(r"(^|\s)(--force\b|-f\b|--force-with-lease\b|\+\S)", a):
        found.append("force push – rewrites the remote history")
    elif part == "api" and a.upper().startswith("DELETE "):
        found.append("deletes")
    return found[:4]
SUDO_RE = re.compile(r"^[A-Za-z0-9 ._/=-]{1,60}$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
JUMP_RE = re.compile(r"^([A-Za-z0-9._-]{1,32}@)?[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")
SSH_KEYS = {"hostname": "HostName", "user": "User", "port": "Port", "proxyjump": "ProxyJump"}


def _conf_files(conf_d):
    return sorted(glob.glob(os.path.join(conf_d, "*.conf")))


def ssh_hosts(conf_d):
    """every alias of every Host block: alias, file, hostname, user, port, proxyjump, hostkeyalias, sudo, access"""
    res = []
    for f in _conf_files(conf_d):
        block = []  # all aliases of the current Host line
        for line in open(f):
            m = META.match(line)
            if m:
                val = access(m.group(2), SSH_ACCESS_DEFAULT) if m.group(1) == "access" else m.group(2)
                for h in block:
                    h[m.group(1)] = val
                continue
            parts = line.strip().split(None, 1)
            if not parts or parts[0].startswith("#"):
                continue
            key, val = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
            if key == "host":
                block = [{"alias": a, "file": os.path.basename(f), "hostname": "", "user": "", "port": "22",
                          "proxyjump": "", "sudo": "", "hostkeyalias": "", "access": SSH_ACCESS_DEFAULT}
                         for a in val.split() if "*" not in a]
                res += block
            elif key in SSH_KEYS or key == "hostkeyalias":
                for h in block:
                    h[key] = val
    return res


def ssh_host(conf_d, alias):
    return next((h for h in ssh_hosts(conf_d) if h["alias"] == alias), None)


def ssh_sudo(conf_d, alias):
    h = ssh_host(conf_d, alias)
    return h["sudo"] if h else ""


def ssh_access(conf_d, alias):
    """access mode of `svc ssh <alias>`: read = no ssh commands, confirm = each needs approval, write = allowed"""
    return access((ssh_host(conf_d, alias) or {}).get("access"), SSH_ACCESS_DEFAULT)


def stacks_dir_guess(compose_ls_json):
    """the stacks directory of a Docker host from `docker compose ls --all --format json`: the directory most
    projects live in (parent of each project's directory) → (dir, number of projects there, all projects); ("", 0, n)
    when there are none or they don't share one"""
    import collections
    try:
        projects = json.loads(compose_ls_json or "[]")
    except ValueError:
        return "", 0, 0
    parents = collections.Counter()
    for p in projects if isinstance(projects, list) else []:
        first = str((p or {}).get("ConfigFiles") or "").split(",")[0].strip()
        if first.startswith("/"):
            parents[os.path.dirname(os.path.dirname(first)) or "/"] += 1
    if not parents:
        return "", 0, len(projects) if isinstance(projects, list) else 0
    best, n = parents.most_common(1)[0]
    return (best, n, len(projects)) if best != "/" else ("", 0, len(projects))


def service_name_for(alias):
    """a service name (lowercase, letters, digits, - and _) for an SSH alias"""
    n = re.sub(r"[^a-z0-9_-]+", "-", str(alias or "").lower()).strip("-_")[:40]
    return n if n and n[0].isalnum() else ("host-" + n)[:40]


def ssh_validate(fields, aliases=None):
    """check user input for a host; raises ValueError with a readable message"""
    if not ALIAS_RE.match(fields.get("alias", "")):
        raise ValueError("alias: letters, digits, . _ - (max 40)")
    if not HOST_RE.match(fields.get("hostname", "")):
        raise ValueError("host: a DNS name or IPv4 address")
    if not USER_RE.match(fields.get("user", "")):
        raise ValueError("user: letters, digits, . _ -")
    port = str(fields.get("port") or "22")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("port: 1–65535")
    jump = fields.get("proxyjump", "")
    if jump and not JUMP_RE.match(jump):
        raise ValueError("ProxyJump: an existing alias or user@host[:port]")
    if jump and jump == fields["alias"]:
        raise ValueError("ProxyJump can't be the host itself")
    sudo = fields.get("sudo", "")
    if sudo and not SUDO_RE.match(sudo):
        raise ValueError("sudo command: letters, digits, space . _ / = - only")
    if fields.get("access", SSH_ACCESS_DEFAULT) not in ACCESS_NAMES:
        raise ValueError("access: read, write or confirm")
    if aliases is not None and fields["alias"] in aliases:
        raise ValueError(f"alias {fields['alias']} exists already")


def _block_lines(fields, extra=()):
    lines = [f"Host {fields['alias']}\n", f"    HostName {fields['hostname']}\n", f"    User {fields['user']}\n"]
    if str(fields.get("port") or "22") != "22":
        lines.append(f"    Port {fields['port']}\n")
    if fields.get("proxyjump"):
        lines.append(f"    ProxyJump {fields['proxyjump']}\n")
    lines += list(extra)
    if fields.get("sudo"):
        lines.append(f"    # tentaclai: sudo={fields['sudo']}\n")
    mode = access(fields.get("access"), SSH_ACCESS_DEFAULT)
    if mode != SSH_ACCESS_DEFAULT:
        lines.append(f"    # tentaclai: access={mode}\n")
    return lines


def _write(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.writelines(lines)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def ssh_add(conf_d, fields, comment="added in tentacontrol"):
    ssh_validate(fields, aliases={h["alias"] for h in ssh_hosts(conf_d)})
    path = os.path.join(conf_d, f"{fields['alias']}.conf")
    if os.path.exists(path):
        raise ValueError(f"{os.path.basename(path)} exists already")
    extra = []
    if fields.get("hostkeyalias"):  # e.g. from an import – the only unmanaged line that is taken over
        if not HOST_RE.match(fields["hostkeyalias"]):
            raise ValueError("HostKeyAlias: a DNS name")
        extra.append(f"    HostKeyAlias {fields['hostkeyalias']}\n")
    os.makedirs(conf_d, exist_ok=True)
    _write(path, [f"# {comment}\n"] + _block_lines(fields, extra))


def _locate(conf_d, alias):
    """(file, lines, start, end) of the Host block that holds exactly this alias"""
    for f in _conf_files(conf_d):
        lines = open(f).read().splitlines(keepends=True)
        start = None
        for i, line in enumerate(lines):
            parts = line.split()
            if parts and parts[0].lower() in ("host", "match"):
                if start is not None:
                    return f, lines, start, i
                if parts[0].lower() == "host" and alias in parts[1:]:
                    if len(parts) > 2:
                        raise ValueError(f"{alias} shares its Host line with other aliases – edit {os.path.basename(f)} by hand")
                    start = i
        if start is not None:
            return f, lines, start, len(lines)
    raise ValueError(f"host {alias} not found")


def ssh_update(conf_d, alias, fields):
    """change HostName/User/Port/ProxyJump/sudo and optionally the alias; keeps unmanaged lines of the block"""
    others = {h["alias"] for h in ssh_hosts(conf_d)} - {alias}
    ssh_validate(fields, aliases=others)
    f, lines, start, end = _locate(conf_d, alias)
    keep = [l for l in lines[start + 1:end] if not META.match(l)
            and (l.split()[0].lower() if l.split() else "") not in SSH_KEYS]
    while keep and not keep[-1].strip():
        keep.pop()
    new = _block_lines(fields, keep)
    if end < len(lines):
        new.append("\n")
    _write(f, lines[:start] + new + lines[end:])
    # a file named after the host follows a rename, if it holds only this host
    target = os.path.join(conf_d, f"{fields['alias']}.conf")
    single = sum(1 for l in lines if l.split() and l.split()[0].lower() == "host") == 1
    if fields["alias"] != alias and single and os.path.basename(f) == f"{alias}.conf" and not os.path.exists(target):
        os.replace(f, target)


def ssh_remove(conf_d, alias):
    f, lines, start, end = _locate(conf_d, alias)
    rest = lines[:start] + lines[end:]
    if any(l.split() and l.split()[0].lower() == "host" for l in rest):
        _write(f, rest)
    else:  # the file only held this host
        os.remove(f)


def ssh_set_sudo(conf_d, alias, cmd):
    h = ssh_host(conf_d, alias)
    if not h:
        raise ValueError(f"host {alias} not found")
    ssh_update(conf_d, alias, dict(h, sudo=(cmd or "").strip()))


def ssh_migrate_access(conf_d):
    """rewrite `# tentaclai: access=ro|rw` to read/write in every host file – returns the changed file names"""
    changed = []
    for f in _conf_files(conf_d):
        lines = open(f).read().splitlines(keepends=True)
        new = []
        for line in lines:
            m = META.match(line)
            if m and m.group(1) == "access" and m.group(2).lower() in ACCESS_ALIASES:
                line = line[:m.start(2)] + ACCESS_ALIASES[m.group(2).lower()] + line[m.end(2):]
            new.append(line)
        if new != lines:
            _write(f + time.strftime(".bak-%Y-%m-%d-access"), lines)
            _write(f, new)
            changed.append(os.path.basename(f))
    return changed


def ssh_known_name(fields):
    """name under which ssh stores the host key: HostKeyAlias, host, or [host]:port for non-default ports"""
    if fields.get("hostkeyalias"):
        return fields["hostkeyalias"]
    port = str(fields.get("port") or "22")
    return fields["hostname"] if port == "22" else f"[{fields['hostname']}]:{port}"


# ---------------------------------------------------------------- skills (Claude Code skillOverrides)
# Every skill Claude Code lists costs context in every request. tentacontrol keeps a mode per skill in
# data/control/skills.json; the entrypoint and tentacontrol write them into Claude's settings.json.
SKILL_MODES = ("on", "user-invocable-only", "off")  # user-invocable-only: only as /command, not offered to the model
SKILLS_OFF_DEFAULT = (  # make no sense in a headless sandbox
    "dataviz", "artifact-design", "artifact-diagramming", "artifact-capabilities", "keybindings-help",
    "fewer-permission-prompts", "claude-in-chrome", "run", "plugin-authoring",
    "anthropic-skills:built-in-browser", "anthropic-skills:chrome-browser", "anthropic-skills:computer-use",
    "anthropic-skills:docs", "anthropic-skills:docx", "anthropic-skills:pptx", "anthropic-skills:xlsx",
    "anthropic-skills:google-workspace", "anthropic-skills:import-memory", "anthropic-skills:morning",
    "anthropic-skills:setup-writing-style",
)


SKILLS_REQUIRED = ("inventory", "onboard")  # tentacontrol starts `claude /inventory` and `claude /onboard <name>` – never off


def skill_mode(state, name):
    m = (state.get("modes") or {}).get(name)
    if name in SKILLS_REQUIRED and m == "off":
        return "on"  # an "off" skill can't even be called as /command
    return m if m in SKILL_MODES else ("off" if name in SKILLS_OFF_DEFAULT else "on")


def skill_overrides(state):
    """{skill: mode} for every skill tentaclai manages (known or default-off); "on" means: no override"""
    names = set(state.get("known") or {}) | set(SKILLS_OFF_DEFAULT) | set(SKILLS_REQUIRED) | set(state.get("modes") or {})
    return {n: skill_mode(state, n) for n in sorted(names)}


def apply_skill_overrides(settings, managed):
    """merge into a settings.json dict – managed skills only, other entries of the user stay"""
    over = settings.setdefault("skillOverrides", {})
    for name, mode in managed.items():
        if mode == "on":
            over.pop(name, None)
        else:
            over[name] = mode
    if not over:
        settings.pop("skillOverrides")
    return settings


# Site skills: procedures of this installation, kept in local/skills/<name>/SKILL.md (root-owned, proposed with
# `svc config put skill`, approved by the user) and copied by `svc sync` into Claude's ~/.claude/skills/<name>/.
SITE_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")  # Claude Code's rule; a dot (.bak-…) is never a skill
SITE_SKILL_MAX = 32 * 1024
_FRONT = re.compile(r"\A---\n(.*?)\n---\n", re.S)


def skill_front(text):
    """the simple `key: value` lines of a SKILL.md frontmatter ({} without one)"""
    m = _FRONT.match((text or "").replace("\r\n", "\n"))
    out = {}
    for line in (m.group(1).splitlines() if m else []):
        k, sep, v = line.partition(":")
        if sep and k.strip() and not k.startswith((" ", "\t")):
            out[k.strip()] = v.strip().strip("\"'")
    return out


def site_skill_problem(name, text):
    """why a site skill can't be written – None if it is fine"""
    if not SITE_SKILL_NAME.match(name or ""):
        return "skill names: a-z 0-9 - (max 64, starting with a letter or digit)"
    if len((text or "").encode()) > SITE_SKILL_MAX:
        return f"a skill is at most {SITE_SKILL_MAX // 1024} KB – keep the steps, link to docs for the rest"
    front = skill_front(text)
    if not front:
        return "a SKILL.md starts with a frontmatter: ---, name: <name>, description: <when to use it>, ---"
    if front.get("name", name) != name:
        return f"the frontmatter says name: {front['name']} – it must be {name}"
    if len(front.get("description", "")) < 10:
        return "the frontmatter needs a description: when Claude should use the skill (one or two sentences)"
    if not _FRONT.sub("", text.replace("\r\n", "\n"), 1).strip():
        return "the skill has no steps below the frontmatter"
    return None


def central_locked(control_dir, section, key):
    """the name of the central server when it enforces this item (central management: <control_dir>/central/locks.json,
    written by tentacontrol), else """""
    try:
        with open(os.path.join(control_dir, "central", "locks.json")) as f:
            locks = json.load(f)
    except (OSError, ValueError):
        return ""
    if f"{section}:{key}" in (locks.get("enforced") or []):
        return locks.get("central") or "the central server"
    return ""


def site_skills(stack_dir):
    """{name: {description, size, mtime}} of local/skills/*/SKILL.md"""
    base = os.path.join(stack_dir, "local", "skills")
    out = {}
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for name in names:
        path = os.path.join(base, name, "SKILL.md")
        if not SITE_SKILL_NAME.match(name) or not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as f:
                text = f.read(SITE_SKILL_MAX + 1)
            st = os.stat(path)
        except OSError:
            continue
        out[name] = {"description": skill_front(text).get("description", ""), "size": st.st_size, "mtime": st.st_mtime}
    return out


# ---------------------------------------------------------------- models (Settings → Models)
# Model and effort per task, from data/control/models.json; "" = Claude Code decides. The default model reaches every
# session (terminal and Remote Control) only through settings.json – `claude remote-control` has no --model.
MODEL_ALIASES = ("fable", "opus", "sonnet", "haiku")
EFFORTS = ("low", "medium", "high", "xhigh")
MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9.\-\[\]]{1,60}$")  # alias or full model id – nothing else reaches settings/frontmatter
MODELS_DEFAULT = {"main": "", "effort": "", "subagents": "sonnet", "commands": "sonnet", "commands_effort": ""}
MODEL_COMMANDS = ("inventory", "onboard")  # slash commands shipped with the image that get the "commands" model


def valid_model(v):
    return v == "" or bool(MODEL_RE.match(v))


def models(state):
    """the effective settings: defaults, overridden by valid values from the state file"""
    out = dict(MODELS_DEFAULT)
    for k, v in (state or {}).items():
        if k not in out or not isinstance(v, str):
            continue
        if (k.endswith("effort") and v in ("",) + EFFORTS) or (not k.endswith("effort") and valid_model(v)):
            out[k] = v
    return out


def apply_models(settings, m):
    """merge into a settings.json dict: model, effortLevel, env.CLAUDE_CODE_SUBAGENT_MODEL ("" removes the entry)"""
    for key, val in (("model", m.get("main", "")), ("effortLevel", m.get("effort", ""))):
        if val:
            settings[key] = val
        else:
            settings.pop(key, None)
    env = settings.setdefault("env", {})
    if m.get("subagents"):
        env["CLAUDE_CODE_SUBAGENT_MODEL"] = m["subagents"]
    else:
        env.pop("CLAUDE_CODE_SUBAGENT_MODEL", None)
    if not env:
        settings.pop("env")
    return settings


def command_frontmatter(text, model="", effort=""):
    """set or remove `model:` and `effort:` in the YAML frontmatter of a slash command file"""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---" or "---" not in [l.strip() for l in lines[1:]]:
        lines = ["---", "---"] + lines
    end = 1 + [l.strip() for l in lines[1:]].index("---")
    head = [l for l in lines[1:end] if not re.match(r"^(model|effort)\s*:", l)]
    head += [f"model: {model}"] if model else []
    head += [f"effort: {effort}"] if effort else []
    return "\n".join(["---"] + head + lines[end:])


def write_model_commands(m, src="/etc/tentaclai/commands", dst=None):
    """the shipped /inventory and /onboard with the "commands" model and effort in their frontmatter (run as claude)"""
    dst = dst or os.path.expanduser("~/.claude/commands")
    for name in MODEL_COMMANDS:
        try:
            text = open(os.path.join(src, f"{name}.md")).read()
        except OSError:
            continue
        out = os.path.join(dst, f"{name}.md")
        with open(out + ".tmp", "w") as f:
            f.write(command_frontmatter(text, m.get("commands", ""), m.get("commands_effort", "")))
        os.replace(out + ".tmp", out)


# ---------------------------------------------------------------- approvals

APPROVAL_HANDOFF = 30  # s; APPROVAL_HANDOFF in .env, 0/off = a Claude session waits for the decision in one go


def approval_handoff(env):
    """seconds a Claude session waits for an approval before svc hands the request back with its link (exit 75),
    so Claude can show the link in the chat and then wait again – 0 = off"""
    v = str(env.get("APPROVAL_HANDOFF", "")).strip().lower()
    if v in ("0", "off", "false", "no"):
        return 0
    try:
        return max(5, min(int(v), 300)) if v else APPROVAL_HANDOFF
    except ValueError:
        return APPROVAL_HANDOFF


# ---------------------------------------------------------------- prompt-injection safeguards
# Hardening and early warning, no guarantee: hidden text is removed, obvious attempts are flagged. The hard limits stay
# svc's access modes, the egress gateway and Claude never holding a secret.

_ZERO_WIDTH = re.compile("[​-‏⁠-⁤﻿­]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def guard_on(env):
    return str(env.get("INJECTION_GUARD", "")).strip().lower() not in ("false", "0", "off", "no")


def clean_untrusted(text):
    """someone else's text without what a human reader can't see → (text, [what was removed])"""
    removed = []
    for rx, what, repl in ((_TAGS, "hidden tag characters", "[hidden text removed]"), (_ZERO_WIDTH, "zero-width characters", ""),
                           (_BIDI, "direction overrides", ""), (_CONTROL, "control characters", "")):
        text, n = rx.subn(repl, text)
        if n:
            removed.append(f"{n} {what}" if repl == "" else what)
    return text, removed


_I = re.IGNORECASE | re.MULTILINE
INJECTION_PATTERNS = [
    ("asks to ignore instructions", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,25}"
        r"\b(instructions?|prompts?|rules|guidelines|directives|messages)\b", _I)),
    ("asks to ignore instructions", re.compile(
        r"\b(ignorier\w*|vergiss|missachte\w*)\b[^.\n]{0,40}\b(anweisungen|instruktionen|regeln|vorgaben)\b", _I)),
    ("tries to change the assistant's role", re.compile(
        r"\b(you are now|from now on,? you|act as (an?|the) (ai|assistant|agent|admin)|du bist (jetzt|ab sofort)|ab sofort bist du)\b", _I)),
    ("claims new instructions", re.compile(r"\b(new|updated|real|actual|hidden) (system )?(instructions?|prompt|orders)\b\s*[:\-]", _I)),
    ("mentions the system prompt", re.compile(r"\b(system prompt|developer message|systemanweisung)\b", _I)),
    ("fake chat or tool markup", re.compile(
        r"(<\|im_(start|end)\|>|\[/?INST\]|<<SYS>>|</?(system|instructions?|assistant|user_query|function_calls|antml:[a-z_]+)>"
        r"|\"role\"\s*:\s*\"system\"|^(Human|Assistant):\s)", _I)),
    ("addresses an AI agent", re.compile(
        r"\b(as an? (ai|llm|language model)|as an? (assistant|agent),? you|dear (ai|assistant|agent|claude)|(hey|hi|attention),? (claude|ai|assistant|agent))\b"
        r"|^\s*claude[,:]", _I)),
    ("addresses an AI agent", re.compile(  # notes for whoever reads this with an AI – plain documents never talk like that
        r"\b(notes?|message|instructions?|info|reminder) (to|for) (any |all )?(ai|llm|automated|autonomous)\b[ \w-]{0,20}\b(assistants?|agents?|models?|systems?|tools?|readers?)\b"
        r"|\b(if|when) you(\s*['’]re| are) (an? )?(ai|llm|language model|ai assistant|ai agent|automated (assistant|agent|system))\b"
        r"|\b(any|every|all) (ai|llm)s?\b[ \w-]{0,15}\breading (this|these)\b"
        r"|\b(hinweis|nachricht|anweisungen?|info|bitte) (für|an) (alle |jeden |jede )?(ki|automatisierte\w*|autonome\w*)\b[ \w-]{0,20}\b(assistent\w*|agent\w*|modell\w*|systeme?\w*|leser\w*)"
        r"|\b(falls|wenn) du (eine |ein )?(ki|llm|sprachmodell|ki-assistent\w*|ki-agent\w*|automatisierte\w* (assistent|agent)\w*) bist\b"
        r"|\b(an alle|liebe) (ki|ki-\w+)\b", _I)),
    ("asks to run commands", re.compile(  # svc is this sandbox's own gateway – no ordinary document tells a reader to run it
        r"\b(run|execute|call|use|type|führe?)\b[^.\n]{0,30}`?\bsvc (docker|compose|ssh|files|mail|db|web|git|config|[a-z0-9_-]+ (POST|PUT|PATCH|DELETE))\b"
        r"|\b(run|execute)\b[^.\n]{0,20}`?(rm -rf /|sudo rm\b|mkfs\b|dd if=)", _I)),
    ("asks to send secrets somewhere", re.compile(
        r"\b(send|forward|upload|post|exfiltrate|leak|e-?mail|schicke?|sende|leite)\b[^\n]{0,80}"
        r"(\b(passwords?|tokens?|secrets?|credentials|api[ _-]?keys?|ssh keys?|private keys?|passw[oö]rter|zugangsdaten)\b|\.env\b|id_(rsa|ed25519))"
        r"[^\n]{0,80}\b(to|an|at|nach)\b\s+\S*([\w.+-]+@[\w-]+\.[\w.]+|https?://)", _I)),
]
_BASE64 = re.compile(r"[A-Za-z0-9+/]{500,}={0,2}")


def injection_signals(text, limit=200_000):
    """short reasons why someone else's text looks like it tries to instruct an AI agent (empty = nothing found) –
    a heuristic: obvious attempts are found, a well-disguised one is not"""
    return [r for r, _ in injection_findings(text, limit)]


def _excerpt(text, start, end, width=80):
    """'line 12: …the text around a hit…' – one line, without hidden characters, for the audit log"""
    part, _ = clean_untrusted(text[max(0, start - width):end + width])
    part = re.sub(r"\s+", " ", part).strip()
    part = ("…" if start > width else "") + part + ("…" if end + width < len(text) else "")
    return f"line {text.count(chr(10), 0, start) + 1}: {part[:240]}"


def injection_findings(text, limit=200_000):
    """[(reason, excerpt)] – injection_signals with where it was found, so the user can judge a finding"""
    if not text:
        return []
    text = text[:limit]
    _, removed = clean_untrusted(text)
    found = []
    if any("tag" in r or "direction" in r for r in removed):
        m = _TAGS.search(text) or _BIDI.search(text)
        hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group() if 0x20 <= ord(c) - 0xE0000 < 0x7F) if m else ""
        found.append((f"hidden text ({', '.join(removed)})",
                      f"hidden text reads: {hidden[:200]}" if hidden else _excerpt(text, m.start(), m.end()) if m else ""))
    for reason, rx in INJECTION_PATTERNS:
        m = rx.search(text)
        if m and reason not in (r for r, _ in found):
            found.append((reason, _excerpt(text, m.start(), m.end())))
    m = _BASE64.search(text)
    if m:
        n = len(m.group())
        found.append(("long base64 block", f"line {text.count(chr(10), 0, m.start()) + 1}: "
                      f"{n // 1024} KB of base64 starting {m.group()[:24]}…" if n >= 1024 else
                      f"line {text.count(chr(10), 0, m.start()) + 1}: {n} characters of base64 starting {m.group()[:24]}…"))
    return found[:5]


def tool_target(tool, tin):
    """what a tool call was about – the file, URL, query or command, shortened to one line – for the audit log"""
    if not isinstance(tin, dict):
        return ""
    if tool.startswith("mcp__"):
        _, server, name = (tool.split("__", 2) + ["", ""])[:3]
        args = ", ".join(f"{k}={json.dumps(v, ensure_ascii=False)[:60]}" for k, v in list(tin.items())[:4])
        v = f"{server} · {name}({args})"
    else:
        key = {"Read": "file_path", "Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path",
               "WebFetch": "url", "WebSearch": "query", "Bash": "command", "Grep": "pattern", "Glob": "pattern",
               "Task": "description", "Agent": "description", "Skill": "skill"}.get(tool)
        if key:
            v = tin.get(key, "")
            if tool in ("Grep", "Glob") and tin.get("path"):
                v = f"{v} in {tin['path']}"
        else:  # any other tool: its first short text argument
            v = next((x for x in tin.values() if isinstance(x, str) and x.strip()), "")
    v = re.sub(r"\s+", " ", str(v or "")).strip()
    return v[:200] + ("…" if len(v) > 200 else "")


def guard_hook_settings(scan=True):
    """the PostToolUse hook in Claude Code's managed settings: tc-guard logs every tool call in the audit log and
    (scan) checks tool results for injection attempts"""
    return {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "timeout": 10,
                                                        "command": "/usr/local/bin/tc-guard" + ("" if scan else " --no-scan")}]}]}


def managed_settings(denied, guard=True):
    """/etc/claude-code/managed-settings.json in the sandbox (root-owned): blocked claude.ai connectors and the hook
    (always there – it writes the audit log; guard only decides whether it scans)"""
    return {"deniedMcpServers": [{"serverName": n} for n in sorted(denied)], "hooks": guard_hook_settings(guard)}


# ---------------------------------------------------------------- audit log
# One format and one implementation for everyone who writes or reads it: svc (sandbox, root), tentacontrol (user
# actions, network, jobs, system) and – through tentacontrol – the egress gateway. JSON lines, flat fields, RFC 3339
# times, an id and an RFC 5424 severity per entry, so a SIEM (or a syslog sender) can take it as it is.
# The active file is <data>/audit.jsonl; at AUDIT_ROTATE it moves to <data>/audit/<UTC time>.jsonl, archives are
# kept AUDIT_RETENTION_DAYS (.env) and removed by tentacontrol.

AUDIT_FILE = "audit.jsonl"
AUDIT_ARCHIVE = "audit"
AUDIT_ROTATE = 10 * 2**20
AUDIT_RETENTION_DAYS = 90
AUDIT_CATEGORIES = ("service", "tool", "network", "admin", "auth", "job", "system")
AUDIT_ACTORS = ("claude", "job", "user", "system")
SEVERITY = {"err": 3, "warning": 4, "notice": 5, "info": 6}
AUDIT_ORIGIN = ("session", "entry", "tmux", "by", "job")  # origin_<key>: where a call came from (svc's origin())
_AUDIT_LIMITS = {"action": 500, "detail": 300, "error": 1000, "service": 120, "part": 20, "mode": 20, "ip": 64, "user": 32, "approver": 40, "grant": 40, "reason": 200, "cid": 64, "process": 200, "process_user": 32, "requested": 40}


def audit_ts(t=None):
    """RFC 3339 with milliseconds and a colon in the offset (2026-10-23T00:42:04.123+02:00) – valid in syslog"""
    from datetime import datetime
    d = datetime.fromtimestamp(time.time() if t is None else t).astimezone()
    return d.isoformat(timespec="milliseconds")


def audit_epoch(ts):
    """seconds of an entry's ts – also the older form without milliseconds and with +0200; 0 if unreadable"""
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(ts)).timestamp()
    except ValueError:
        try:
            return datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%S%z").timestamp()
        except ValueError:
            return 0


def audit_severity(e):
    d = e.get("decision", "")
    if e.get("category") == "auth" and d in ("failed", "blocked"):
        return SEVERITY["warning"]
    if d in ("error", "failed"):
        return SEVERITY["err"]
    if d in ("denied", "blocked", "flagged", "expired"):
        return SEVERITY["warning"]
    if d in ("approved", "auto") or e.get("category") in ("admin", "auth"):
        return SEVERITY["notice"]
    return SEVERITY["info"]


def audit_origin(e):
    """the origin of an entry as a dict ({"session": …, "tmux": …}) – from origin_* or the older nested "from" """
    o = {k: e[f"origin_{k}"] for k in AUDIT_ORIGIN if e.get(f"origin_{k}")}
    if not o and isinstance(e.get("from"), dict):
        o = {k: str(v) for k, v in e["from"].items() if k in AUDIT_ORIGIN and v}
    return o


def audit_normalize(e, raw=""):
    """fill in what older entries lack (id, category, actor, severity, flat origin, access names) – in place, returns e"""
    import hashlib
    if not e.get("id"):
        e["id"] = hashlib.sha1((raw or json.dumps(e, sort_keys=True)).encode()).hexdigest()[:16]
    if isinstance(e.get("from"), dict):
        for k, v in audit_origin(e).items():
            e.setdefault(f"origin_{k}", v)
        e.pop("from")
    if e.get("category") not in AUDIT_CATEGORIES:
        e["category"] = {"network": "network", "claude": "tool"}.get(e.get("part"), "service")
    if e.get("actor") not in AUDIT_ACTORS:
        e["actor"] = ("user" if e["category"] in ("admin", "auth") else "system" if e.get("origin_by") == "root"
                      else "job" if e.get("origin_job") else "claude")
    if e.get("mode") in ACCESS_ALIASES:  # entries written before v0.16
        e["mode"] = ACCESS_ALIASES[e["mode"]]
    if not isinstance(e.get("severity"), int):
        e["severity"] = audit_severity(e)
    return e


def audit_entry(category, service, action, decision, actor="", part="", mode="", origin=None, **extra):
    """a new entry with every field set and cut to size (extra: exit, seconds, detail, error, excerpts, count, ip)"""
    e = {"ts": audit_ts(), "id": os.urandom(8).hex(), "category": category, "actor": actor, "service": str(service),
         "part": str(part or category), "mode": str(mode or ""), "action": re.sub(r"[\r\n]+", " ", str(action)), "decision": decision}
    for k, v in (origin or {}).items():
        if k in AUDIT_ORIGIN and v:
            e[f"origin_{k}"] = str(v)[:80]
    for k, v in extra.items():
        if v is not None and v != "" and v != []:
            e[k] = v
    for k, n in _AUDIT_LIMITS.items():
        if isinstance(e.get(k), str):
            e[k] = e[k][:n]
    if e.get("excerpts"):
        e["excerpts"] = [{"reason": str(x.get("reason", ""))[:80], "text": str(x.get("text", ""))[:300]} for x in e["excerpts"][:5]]
    return audit_normalize(e)


def audit_write(data_dir, entry):
    """append one entry (from audit_entry) to <data_dir>/audit.jsonl, rotating at AUDIT_ROTATE – raises OSError only"""
    import fcntl
    path = os.path.join(data_dir, AUDIT_FILE)
    os.makedirs(data_dir, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    old = os.umask(0o077)
    try:
        with open(path + ".lock", "a") as lock:  # one lock for every writer (svc and tentacontrol share the directory)
            fcntl.flock(lock, fcntl.LOCK_EX)
            if os.path.exists(path) and os.path.getsize(path) > AUDIT_ROTATE:
                arch = os.path.join(data_dir, AUDIT_ARCHIVE)
                os.makedirs(arch, exist_ok=True)
                os.replace(path, os.path.join(arch, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + ".jsonl"))
            with open(path, "a") as f:
                f.write(line)
    finally:
        os.umask(old)


def _audit_files(data_dir, cutoff=0):
    """newest first: the active file, then archives whose last entry (= the rotation time in the name) is after cutoff"""
    import calendar
    files = [os.path.join(data_dir, AUDIT_FILE)]
    arch = os.path.join(data_dir, AUDIT_ARCHIVE)
    try:
        names = sorted((n for n in os.listdir(arch) if n.endswith(".jsonl")), reverse=True)
    except OSError:
        names = []
    for n in names:
        try:
            end = calendar.timegm(time.strptime(n[:16], "%Y%m%dT%H%M%SZ"))
        except ValueError:
            end = 0
        files.append(os.path.join(arch, n))
        if end and end < cutoff:
            break  # everything in older archives is older still
    return files


_AUDIT_INTENT = re.compile(r'"intent": "([0-9a-f]+)"')
_AUDIT_STARTED = '"decision": "started"'
_AUDIT_ID = re.compile(r'"id": "([0-9a-f]+)"')


def audit_lines(data_dir, cutoff=0, settled=False):
    """raw lines, newest first, across the active file and the archives. settled: without the "started" entry of a
    write whose result is logged (the result names it in "intent") – a "started" entry stays when the write never
    finished (svc killed, timeout) or is still running"""
    done = set()
    for path in _audit_files(data_dir, cutoff):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            if settled:
                if m := _AUDIT_INTENT.search(line):
                    done.add(m.group(1))
                elif _AUDIT_STARTED in line and (m := _AUDIT_ID.search(line)) and m.group(1) in done:
                    continue
            yield line


AUDIT_SEARCH = ("action", "service", "part", "detail", "error", "excerpts", "ip", "reason")  # the stored fields words are searched in
AUDIT_RAW = ("action", "target", "decision", "mode", "ip", "user", "reason", "cid")  # search keys whose value is stored as it is


def _audit_raw_tests(terms):
    """substrings every matching line contains: the words, and the values of field terms that are stored as they are
    (one positive term for the key – several are OR – no wildcard, nothing JSON would escape, no older spelling)"""
    keys = [k for neg, k, v in terms if k and not neg]
    return [v for neg, k, v in terms if not neg and (k is None or (
        k in AUDIT_RAW and keys.count(k) == 1 and "*" not in v and v.isascii() and not set(v) & set('"\\')
        and not (k == "mode" and v in ACCESS_ALIASES.values())))]


def audit_read(data_dir, limit=200, since=0, until=0, after="", query=None, source=None):
    """entries newest first: since/until in epoch seconds (0 = open), query a search (audit_query: field:value terms and
    words; each entry then carries its audit_view as "_view", source names the source as in audit_view), after the id
    of the last entry already shown ("load more") → (entries, more): more is True when further entries match"""
    terms = audit_query(query) if isinstance(query, str) else list(query or [])
    raw = _audit_raw_tests(terms)
    out, skipping = [], bool(after)
    for line in audit_lines(data_dir, since, settled=True):
        if raw and not all(w in line.lower() for w in raw):
            continue  # quick test on the raw line first; the fields are checked below
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        audit_normalize(e, line)
        t = audit_epoch(e.get("ts"))
        if since and t < since:
            if t:
                break  # the log is in time order – everything further back is older
            continue
        if skipping:
            skipping = e["id"] != after
            continue
        if until and t > until:
            continue
        if terms:
            e["_view"] = audit_view(e, source)
            if audit_fails(e, e["_view"], terms):
                continue
        if len(out) >= limit:
            return out, True
        out.append(e)
    return out, False


# ---- the view: one name per field for the page, the search, the facets and the export (the stored fields stay as they are)

AUDIT_TYPES = {"service": "svc", "tool": "tool", "network": "network", "admin": "admin", "auth": "sign-in", "job": "job",
               "system": "system"}  # category → the word shown as type
AUDIT_OUTCOMES = ("ok", "approved", "started", "flagged", "denied", "blocked", "expired", "failed")
AUDIT_FIELDS = ("outcome", "actor", "type", "target", "source", "user", "approver")  # the facets, in this order
AUDIT_KEYS = {"actor": "actor", "user": "user", "source": "source", "type": "type", "target": "target",
              "action": "action", "outcome": "outcome", "decision": "decision", "mode": "mode", "ip": "ip", "approver": "approver", "grant": "grant",
              "reason": "reason", "cid": "cid", "process": "process", "requested": "requested", "attempts": "attempts",
              "category": "type", "service": "target"}  # search keys (category/service: the stored names)
AUDIT_SEARCH_KEYS = tuple(k for k, v in AUDIT_KEYS.items() if k == v)  # the search keys to name in a hint (without the stored aliases)
_AUDIT_TOKEN = re.compile(r'(-?)([A-Za-z_]+):"([^"]*)"|(-?)([A-Za-z_]+):(\S+)|(-?)"([^"]*)"|(-?)(\S+)')


AUDIT_TONES = {"ok": "ok", "allowed": "ok", "read": "ok", "auto": "ok", "approved": "ok", "flagged": "flagged", "warn": "flagged",
               "started": "flagged",
               "blocked": "denied", "expired": "denied", "denied": "denied", "failed": "failed"}  # outcome → colour / histogram


def audit_outcome(e):
    """one word for decision and result: the decision as written (allowed, read, auto, approved, denied …), failed
    when the call itself failed (error, exit ≠ 0) – tentaclAI Enterprise shows the same word"""
    d = e.get("decision", "") or "ok"
    if d in ("denied", "blocked", "expired"):
        return d
    if d in ("error", "failed") or e.get("error") or (isinstance(e.get("exit"), int) and e["exit"] != 0):
        return "failed"
    return d


def audit_source(e):
    """where an entry came from, from its stored fields (tentacontrol names sessions and jobs more readably)"""
    o = audit_origin(e)
    if o.get("job"):
        return f"job {o['job']}"
    if o.get("by") == "root":
        return "tentacontrol / host"
    for k in ("tmux", "entry"):
        if o.get(k):
            return o[k]
    if o.get("session"):
        return f"session {o['session'][:8]}"
    return e.get("ip", "")


_OLD_GRANT = re.compile(r"^(?:grant until (\d\d:\d\d) \((.+)\)|(.+?) \+ (\d+ min))(?: · (always allowed|on the blocklist))?$")


def audit_approval(e):
    """(approver, grant) of an approval – stored since accounts; older entries had both in detail
    ("mwa + 15 min", "grant until 14:20 (mwa)", "… · always allowed"); "tentacontrol (IP)" named no one"""
    if e.get("approver") or e.get("grant") or e.get("mode") != "confirm":
        return e.get("approver", ""), e.get("grant", "")
    d = str(e.get("detail", ""))
    lasting = {"always allowed": "always", "on the blocklist": "blocklist"}
    m = _OLD_GRANT.match(d)
    if m:
        who, grant = (m.group(2), f"until {m.group(1)}") if m.group(1) else (m.group(3), m.group(4))
        grant = lasting.get(m.group(5), grant)
    else:
        who, _, tail = d.partition(" · ")
        grant = lasting.get(tail, "")
    if who.startswith("tentacontrol") or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,31}", who):
        who = ""
    return who, grant


def audit_view(e, source=None):
    """the fields of the page and the CSV: time, actor, user, source, type, target, action, outcome (+ approver, grant,
    the reason of a denial, cid – the correlation id: one svc call, or one request in tentacontrol; for a network
    request the process that opened it, when it was first requested and how many connections waited for it)"""
    approver, grant = audit_approval(e)
    return {"approver": approver, "grant": grant, "time": e.get("ts", ""), "actor": e.get("actor", ""), "user": e.get("user", ""),
            "source": (source or audit_source)(e) or "", "type": AUDIT_TYPES.get(e.get("category"), e.get("category", "")),
            "target": str(e.get("service", "")), "action": str(e.get("action", "")), "outcome": audit_outcome(e),
            "decision": e.get("decision", ""), "mode": e.get("mode", ""), "ip": e.get("ip", ""), "reason": e.get("reason", ""),
            "cid": e.get("cid", ""), "process": e.get("process", "") + (f" ({e['process_user']})" if e.get("process") and e.get("process_user") else ""), "requested": e.get("requested", ""),
            "attempts": e.get("attempts", "") if isinstance(e.get("attempts"), int) and e["attempts"] > 1 else ""}


def audit_query(text):
    """a search → terms (negated, key, value): key:value, key:"with spaces", -key:value (not), words and "phrases"
    (key None). Unknown keys stay words; type takes the stored category too (type:auth = type:sign-in)."""
    terms = []
    for m in _AUDIT_TOKEN.finditer(text or ""):
        g = m.groups()
        if g[1] or g[4]:
            neg, key, val = (g[0], g[1], g[2]) if g[1] else (g[3], g[4], g[5])
            k = AUDIT_KEYS.get(key.lower())
            if k is None:
                terms.append((False, None, m.group(0).lower()))
                continue
            val = val.strip().lower()
            if k == "type":
                val = AUDIT_TYPES.get(val, val)
            if val:
                terms.append((bool(neg), k, val))
        else:
            neg, val = (g[6], g[7]) if g[7] is not None else (g[8], g[9])
            if val and val != "-":
                terms.append((bool(neg), None, val.lower()))
    return terms


def audit_unknown_keys(text):
    """field names in a search that aren't fields (e.g. status:denied) – audit_query treats them as words, so a hint
    can name the real ones. A value starting with / (http://…) is no field."""
    out = []
    for m in _AUDIT_TOKEN.finditer(text or ""):
        key, val = (m.group(2), m.group(3)) if m.group(2) else (m.group(5), m.group(6))
        if key and key.lower() not in AUDIT_KEYS and not (val or "").startswith("/") and key.lower() not in out:
            out.append(key.lower())
    return out


def audit_query_str(terms):
    """terms back to a search text"""
    out = []
    for neg, k, v in terms:
        q = f'"{v}"' if (" " in v or not v) else v
        out.append(("-" if neg else "") + (f"{k}:{q}" if k else q))
    return " ".join(out)


def _audit_value_match(pattern, value):
    import fnmatch
    value = str(value).lower()
    return fnmatch.fnmatchcase(value, pattern) if "*" in pattern else value == pattern


def audit_fails(e, view, terms):
    """the keys whose terms an entry doesn't meet (None for the words) – empty: it matches. Terms with the same key are
    OR, different keys AND, negated ones NOT."""
    inc, fails = {}, set()
    for neg, k, v in terms:
        if k is None:
            text = (" ".join(json.dumps(e.get(x, ""), ensure_ascii=False) for x in AUDIT_SEARCH) + " "
                    + " ".join(str(view.get(x, "")) for x in ("user", "source", "target", "action"))).lower()
            if (v in text) == neg:
                fails.add(None)
        elif neg:
            if _audit_value_match(v, view.get(k, "")):
                fails.add(k)
        else:
            inc.setdefault(k, []).append(v)
    for k, vals in inc.items():
        if not any(_audit_value_match(v, view.get(k, "")) for v in vals):
            fails.add(k)
    return fails


def audit_facets(entries, terms, fields=AUDIT_FIELDS):
    """{field: [(value, count), …]} – each field counted under all the *other* terms, so the values of a chosen field
    keep their numbers; entries carry their "_view" (audit_read with a query, or audit_view)"""
    out = {f: {} for f in fields}
    for e in entries:
        v = e.get("_view") or audit_view(e)
        fails = audit_fails(e, v, terms)
        if len(fails) > 1 or None in fails:
            continue
        for f in fields:
            if fails and f not in fails:
                continue
            val = v.get(f, "")
            if val:
                out[f][val] = out[f].get(val, 0) + 1
    return {f: sorted(c.items(), key=lambda x: (-x[1], x[0])) for f, c in out.items()}


AUDIT_BUCKETS = (30, 60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400)


def audit_bucket(span):
    """bucket width for a time span: about 48 bars"""
    return next((b for b in AUDIT_BUCKETS if span / b <= 60), AUDIT_BUCKETS[-1])


def audit_histogram(entries, since, until, width=None):
    """[(start, {"ok": n, "denied": n, "failed": n, "flagged": n}), …] oldest first, for entries that match (their
    "_view" outcome); denied also counts blocked and expired"""
    width = width or audit_bucket(until - since)
    start = since - since % width
    n = max(1, int((until - start) // width) + 1)
    bars = [(start + i * width, {"ok": 0, "denied": 0, "failed": 0, "flagged": 0}) for i in range(n)]
    for e in entries:
        t = audit_epoch(e.get("ts"))
        i = int((t - start) // width)
        if 0 <= i < n:
            o = (e.get("_view") or audit_view(e))["outcome"]
            bars[i][1][AUDIT_TONES.get(o, "ok")] += 1
    return bars


def audit_prune(data_dir, days=AUDIT_RETENTION_DAYS, now=None):
    """remove archives whose newest entry is older than days; also moves a pre-v0.20 audit.jsonl.1 into the archive
    → number of files removed"""
    arch = os.path.join(data_dir, AUDIT_ARCHIVE)
    old = os.path.join(data_dir, AUDIT_FILE + ".1")
    if os.path.exists(old):
        os.makedirs(arch, exist_ok=True)
        os.replace(old, os.path.join(arch, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(os.path.getmtime(old))) + ".jsonl"))
    cutoff = (now or time.time()) - max(1, int(days)) * 86400
    removed = 0
    for path in _audit_files(data_dir)[1:]:
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            pass
    return removed


def audit_retention(env):
    try:
        return max(1, int(env.get("AUDIT_RETENTION_DAYS") or AUDIT_RETENTION_DAYS))
    except ValueError:
        return AUDIT_RETENTION_DAYS


AUDIT_STORED = ("ts", "id", "severity", "category", "actor", "user", "service", "part", "mode", "action", "decision",
                "approver", "grant", "reason", "exit", "seconds", "count", "detail", "error", "ip", "origin_session", "origin_entry", "origin_tmux",
                "origin_job", "origin_by", "excerpts")  # the flat stored fields (syslog structured data)
AUDIT_CSV = ("time", "actor", "user", "source", "type", "target", "action", "outcome", "approver", "grant", "reason", "decision",
             "part", "mode", "exit",
             "seconds", "count", "detail", "error", "ip", "id", "severity", "excerpts",
             "cid", "process", "requested", "attempts")  # the view's names, then details (new ones at the end)


def audit_export(entries, fmt="jsonl"):
    """export lines: jsonl (one entry per line, as stored) or csv (AUDIT_CSV – the names of the page – header first,
    excerpts as one cell)"""
    if fmt == "jsonl":
        for e in entries:
            yield json.dumps({k: v for k, v in e.items() if not k.startswith("_")}, ensure_ascii=False) + "\n"
        return
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(AUDIT_CSV)
    yield buf.getvalue()
    buf.seek(0)
    buf.truncate()
    for e in entries:
        row = []
        view = e.get("_view") or audit_view(e)
        for k in AUDIT_CSV:
            v = view[k] if k in view else e.get(k, "")
            if k == "excerpts":
                v = " | ".join(f"{x.get('reason', '')}: {x.get('text', '')}" for x in v or [])
            v = str(v)
            row.append("'" + v if v[:1] in ("=", "+", "-", "@") and k not in ("exit", "seconds") else v)  # no formulas
        w.writerow(row)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()


SYSLOG_FACILITY = 13  # "log audit"
SYSLOG_SDID = "tentaclai@32473"  # 32473: the example enterprise number of RFC 5612 – replace with a registered one
_SD_ESCAPE = re.compile(r'(["\\\]])')


def audit_syslog(e, hostname="-", facility=SYSLOG_FACILITY, sdid=SYSLOG_SDID):
    """one entry as an RFC 5424 message: <PRI>1 TIMESTAMP HOST tentaclai - MSGID [SD] MSG (UTF-8, BOM before MSG).
    Not sent anywhere in Community – the format is here so a sender only needs the transport (RFC 5425, TLS)."""
    def sdname(k):
        return re.sub(r"[^A-Za-z0-9_.-]", "_", k)[:32]
    host = re.sub(r"[^!-~]", "", hostname or "-")[:255] or "-"
    params = []
    for k in AUDIT_STORED:
        if k in ("ts", "excerpts") or e.get(k) in (None, ""):
            continue
        value = _SD_ESCAPE.sub(r"\\\1", str(e[k]))
        params.append(f'{sdname(k)}="{value}"')
    msgid = re.sub(r"[^!-~]", "", str(e.get("category") or "-"))[:32] or "-"
    msg = f"{e.get('decision', '')}: {e.get('service', '')} {e.get('action', '')}".strip()
    for x in e.get("excerpts") or []:
        msg += f" | {x.get('reason', '')}: {x.get('text', '')}"
    ts = e.get("ts") or "-"
    if "T" in ts and re.search(r"[+-]\d{4}$", ts):
        ts = ts[:-2] + ":" + ts[-2:]  # an older entry: +0200 → +02:00
    pri = facility * 8 + int(e.get("severity", SEVERITY["info"]))
    return f"<{pri}>1 {ts} {host} tentaclai - {msgid} [{sdid} {' '.join(params)}] ﻿{msg}"
