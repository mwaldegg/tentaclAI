"""svc core: paths, privileges (sudo, the users claude and tcrun, files handed to Claude), loading services, systems and
the .env, running client tools, tunnels through the egress gateway."""
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile

import tclib  # shared with tentacontrol (lib/tclib.py)


def _read(path):
    try:
        return open(path).read().strip()
    except OSError:
        return ""


CLAUDE_USER, RUN_USER = "claude", "tcrun"
# egress gateway (all outbound traffic of the sandbox) – also under sudo, where the environment is reset
PROXY = _read("/etc/tentaclai/proxy")
if PROXY:
    for _k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        os.environ.setdefault(_k, PROXY)
    for _k in ("no_proxy", "NO_PROXY"):
        os.environ.setdefault(_k, "localhost,127.0.0.1,tentacontrol")
PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY")
# under sudo the environment is reset – the stack path then comes from a root-owned file written by the entrypoint
TC_DIR = os.environ.get("TC_DIR") or _read("/etc/tentaclai/tc-dir") or "/opt/tentaclai"
SERVICES_DIR = os.environ.get("SVC_DIR", os.path.join(TC_DIR, "services"))
SYSTEMS_DIR = os.path.join(TC_DIR, "systems")
SKILLS_DIR = os.path.join(TC_DIR, "local", "skills")
PARTS = tclib.PARTS
SSH_CONF_D = os.path.expanduser("~/.ssh/config.d")
# Values from the stack's .env win over the container environment, so new tokens work without recreating
ENV_FILE = os.environ.get("SVC_ENV_FILE", os.path.join(TC_DIR, ".env"))
CATALOG = os.environ.get("SVC_CATALOG", "/workspace/SERVICES.md")
REPO_ROOT = os.environ.get("SVC_REPO_ROOT", "/workspace/repos")
STATE = os.path.expanduser("~/.config/tentaclai/mcp-managed.json")
SKILLS_STATE = os.path.expanduser("~/.config/tentaclai/skills-managed.json")
OAUTH_CACHE = os.path.expanduser("~/.cache/tentaclai/oauth")
RO_DOCKER = {"ps", "inspect", "logs", "images", "info", "version", "stats", "top", "port", "diff", "history", "events",
             "network", "volume", "image", "container", "system", "context"}
RO_SUB = {"ls", "list", "inspect", "ps", "logs", "df", "info", "top", "port", "diff", "history", "show"}
RO_COMPOSE = {"ps", "logs", "config", "ls", "images", "top", "port", "version", "events"}
HOOK_MARK = "# tentaclai pre-push hook"
MIRRORS = os.path.expanduser("~/.cache/tentaclai/git")
ORIG_CWD = "/"


# ---------- privileges ----------

def elevate():
    """Claude (non-root) → re-run through sudo as root; root (entrypoint, tentacontrol) runs directly"""
    if os.geteuid() != 0 and os.path.exists("/etc/sudoers.d/tentaclai"):
        os.execvp("sudo", ["sudo", "-n", "--", os.path.abspath(sys.argv[0]), *sys.argv[1:]])


def privileged():
    return os.geteuid() == 0


def via_sudo():
    """called by Claude through sudo (not by root directly)"""
    return privileged() and "SUDO_UID" in os.environ


SESSION_ID_RE = re.compile(r"^(cse_[A-Za-z0-9]{10,60}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_origin = None
JOB_RE = re.compile(r"^[a-z0-9]{6,40}$")
_job = None


def job():
    """the scheduled job a call belongs to, or None. tentacontrol runs a job's Claude under a wrapper process
    `sh -c … tc-job=<run id>` and lists the run in root's job-runs.json; svc looks for that marker in the command lines
    of its ancestors (/proc/<pid>/cmdline – readable without ptrace, unlike another user's environment). Claude can
    start processes with markers of its own, so the strictest one wins: any marker that isn't a registered standard run
    makes the call read-only."""
    global _job
    if _job is not None:
        return _job or None
    found = [m for _, args in _ancestors(os.getppid()) for m in _job_marks(args)]
    if not found:
        _job = {}
        return None
    try:
        with open(os.path.join(TC_DIR, "data", "control", "job-runs.json")) as f:
            runs = json.load(f)
    except (OSError, ValueError):
        runs = {}
    known = [runs.get(r) for r in found if JOB_RE.match(r) and isinstance(runs.get(r), dict)]
    ro = len(known) < len(found) or any(k.get("profile") != "standard" for k in known)
    # a job limited to the tentacles its task names: only those – the intersection if markers disagree
    allows = [set(map(str, k["allow"])) for k in known if isinstance(k.get("allow"), list)]
    first = found[-1]  # the outermost marker – the one tentacontrol set
    _job = {"run": first if JOB_RE.match(first) else "", "read_only": ro,
            "allow": set.intersection(*allows) if allows else None}
    return _job


def _ancestors(pid, proc="/proc"):
    """(pid, argv as bytes) of a process and its ancestors, nearest first – cmdline and stat are readable for any user"""
    for _ in range(64):
        if pid <= 1:
            return
        try:
            with open(os.path.join(proc, str(pid), "cmdline"), "rb") as f:
                args = f.read().split(b"\0")
            with open(os.path.join(proc, str(pid), "stat")) as f:
                parent = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            return
        yield pid, args
        pid = parent


def _job_marks(args):
    return [a[7:].decode(errors="replace") for a in args if a.startswith(b"tc-job=")]


def job_read_only():
    j = job()
    return bool(j and j["read_only"])


def job_allows(name):
    """False when a scheduled job is limited to other tentacles"""
    j = job()
    return not j or j.get("allow") is None or name in j["allow"]


def origin():
    """where a call comes from – the Claude session, its kind and tmux session – for approvals and the audit log.
    Taken from the four variables sudo keeps (see the sudoers file); Claude controls them, so this is a hint for the user,
    not a security feature: every value is checked strictly before it is passed on."""
    global _origin
    if _origin is not None:
        return _origin
    o = {}
    if not via_sudo():
        o["by"] = "root"  # tentacontrol, the entrypoint or a root shell
    else:
        if job() and job()["run"]:
            o["job"] = job()["run"]
        o.update(_session(os.environ))
    _origin = o
    return o


def _session(env):
    """the Claude session, entry point and tmux session named by a process environment – each value checked strictly"""
    o = {}
    if SESSION_ID_RE.match(env.get("CLAUDE_CODE_SESSION_ID", "")):
        o["session"] = env["CLAUDE_CODE_SESSION_ID"]
    if re.fullmatch(r"[a-z][a-z-]{0,19}", env.get("CLAUDE_CODE_ENTRYPOINT", "")):
        o["entry"] = env["CLAUDE_CODE_ENTRYPOINT"]
    return {**o, **_tmux(env)}


def _tmux(env):
    """{"tmux": session name} from a process's TMUX/TMUX_PANE – asked as Claude, it's Claude's tmux server"""
    pane, sock = env.get("TMUX_PANE", ""), env.get("TMUX", "").split(",")[0]
    if re.fullmatch(r"%\d{1,5}", pane) and re.fullmatch(r"/tmp/tmux-\d+/[A-Za-z0-9_.-]+", sock):
        try:
            r = subprocess.run(["tmux", "-S", sock, "display-message", "-p", "-t", pane, "#S"], capture_output=True,
                               text=True, timeout=3, **as_user(CLAUDE_USER))
            name = r.stdout.strip()
            if r.returncode == 0 and re.fullmatch(r"[A-Za-z0-9._-]{1,40}", name):
                return {"tmux": name}
        except (OSError, subprocess.SubprocessError):
            pass
    return {}


def port_socket(port, proc="/proc"):
    """the sandbox's TCP connection from local port `port` (to the egress gateway) → (socket inode, owner uid) or None"""
    for f in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc, "net", f)) as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            col = row.split()
            if len(col) > 9 and col[3] != "0A" and int(col[1].rsplit(":", 1)[1], 16) == port and col[9] != "0":
                return col[9], int(col[7])  # 0A = LISTEN: a server on the same number is not it
    return None


def socket_pid(inode, proc="/proc"):
    """the process with an fd on that socket → pid or None (only readable for the process's own user – root in the
    sandbox has no CAP_SYS_PTRACE)"""
    want = f"socket:[{inode}]"
    for d in os.listdir(proc):
        if not d.isdigit():
            continue
        try:
            for fd in os.listdir(os.path.join(proc, d, "fd")):
                if os.readlink(os.path.join(proc, d, "fd", fd)) == want:
                    return int(d)
        except OSError:
            continue
    return None


def as_uid(uid, fn):
    """fn() in a child process running as uid (root stays root) → its JSON-able result, None on failure"""
    if uid == 0 or not privileged():
        return fn()
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return None
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # the child: drop to the user, answer through the pipe, never return into svc. Changing the uid makes
        # it non-dumpable – that user can't attach to it or read its memory (svc's .env values are in there)
        try:
            os.close(r)
            os.setgroups([])
            os.setgid(pw.pw_gid)
            os.setuid(uid)
            os.write(w, json.dumps(fn()).encode())
        finally:
            os._exit(0)
    os.close(w)
    out = b""
    while chunk := os.read(r, 65536):
        out += chunk
    os.close(r)
    os.waitpid(pid, 0)
    try:
        return json.loads(out) if out else None
    except ValueError:
        return None


def process_origin(pid, proc="/proc"):
    """who started a process: its command and user and – from the nearest ancestor that has them – the Claude session,
    entry point and tmux session, or the job (the outermost tc-job marker, like job()). A hint like origin(): Claude
    controls its own processes' environment and names"""
    try:
        user = pwd.getpwuid(os.stat(os.path.join(proc, str(pid))).st_uid).pw_name
    except (OSError, KeyError):
        return {}
    out, o = {"user": user}, {}
    for chain, args in _ancestors(pid, proc):
        if "command" not in out:  # the process itself, the first in the walk
            out["command"] = " ".join(a.decode(errors="replace") for a in args if a)[:200]
        marks = [m for m in _job_marks(args) if JOB_RE.match(m)]
        if marks:
            o = {"job": marks[0]}
        elif not o:
            try:  # another user's environment is unreadable (sudo, docker exec) – go on with its parent
                with open(os.path.join(proc, str(chain), "environ"), "rb") as f:
                    env = dict(x.decode(errors="replace").split("=", 1) for x in f.read().split(b"\0") if b"=" in x)
            except OSError:
                env = {}
            found = _session(env)
            o = found if "session" in found else {}
    if "command" not in out:
        return {}
    out["origin"] = o
    return out


def _account(user):
    try:
        return pwd.getpwnam(user)
    except KeyError:
        return None


def as_user(user, env=None, cwd=None):
    """subprocess kwargs to run a command as another user with a minimal environment (no secrets of other parts)"""
    pw = _account(user) if privileged() else None
    base = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TERM", "TZ", "COLUMNS", "LINES") + PROXY_VARS if k in os.environ}
    base.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    if pw is None:  # not root (tests outside the image) – run as ourselves
        return {"env": {**os.environ, **(env or {})}, **({"cwd": cwd} if cwd else {})}
    base.update(HOME=pw.pw_dir, USER=user, LOGNAME=user)
    return {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": [], "umask": 0o022,
            "env": {**base, **(env or {})}, "cwd": cwd or (ORIG_CWD if _can_enter(pw, ORIG_CWD) else pw.pw_dir)}


def _can_enter(pw, path):
    try:
        st = os.stat(path)
    except OSError:
        return False
    mode = st.st_mode
    return bool(mode & 0o001) or (st.st_uid == pw.pw_uid and mode & 0o100) or (st.st_gid == pw.pw_gid and mode & 0o010)


def runner(env=None):
    """client tools (curl, psql, mariadb …) run as tcrun: they only get their own secret, never root"""
    return as_user(RUN_USER, env)


def give(path, user):
    """hand a file/tree created by root to a user (Claude's workspace files, tcrun's secret files)"""
    pw = _account(user) if privileged() else None
    if pw is None:
        return
    if os.path.isdir(path) and not os.path.islink(path):
        for root, dirs, files in os.walk(path):
            for n in dirs + files:
                os.lchown(os.path.join(root, n), pw.pw_uid, pw.pw_gid)
    os.lchown(path, pw.pw_uid, pw.pw_gid)


def stage_dir(owner=None):
    """private temp dir for handing files between root and Claude (rsync, git bundles)"""
    d = tempfile.mkdtemp(prefix="svc-", dir="/tmp")
    if owner:
        give(d, owner)
    return d


# ---------- loading ----------

ENV = {}  # values for ${VAR}: the container environment, overridden by the stack's .env
CID = os.urandom(6).hex()  # correlation id of this call: in each of its audit entries and its approval request


def load_env_file():
    """.env values (all service tokens) are kept here – never in os.environ, so ssh/docker/compose/git child processes
    don't inherit them (a local `docker compose` would even prefer them over a stack's own .env)"""
    ENV.clear()
    ENV.update(os.environ)
    ENV.update(tclib.read_env(ENV_FILE))


def _report(errors, prefix=""):
    for name, e in errors.items():
        print(f"svc: {prefix}{name}.json: invalid JSON ({e})", file=sys.stderr)


def load():
    errors = {}
    services = {s["name"]: s for s in tclib.load_services(SERVICES_DIR, load_systems(), errors).values()}
    _report(errors)
    return services


def load_systems():
    """systems/*.json – groups of services (one host or appliance) with shared description, SSH host and rules"""
    errors = {}
    systems = tclib.load_systems(TC_DIR, errors)
    _report(errors, "systems/")
    return systems


def members(services, system):
    return [n for n, s in services.items() if s.get("system") == system]


variables = tclib.variables
enabled = tclib.enabled


def render(obj):
    return tclib.render(obj, ENV)


def missing_vars(part):
    return tclib.missing(part, ENV)


def status(svc):
    return tclib.status_text(svc, ENV)


def kinds(svc):
    return "+".join(tclib.kinds(svc)) or "-"


def ssh_sudo(alias):
    """sudo prefix configured for an SSH host ('# tentaclai: sudo=sudo -n' inside its Host block), '' = none"""
    return tclib.ssh_sudo(SSH_CONF_D, alias)


# ---------- shared: service part lookup ----------


def part_services(services, part):
    return {n: s for n, s in services.items() if part in s}


def tunnel(host, port):
    """local port that leads to host:port through the egress gateway (for clients without proxy support, e.g. psql);
    returns (address, port) – the target itself when there is no gateway"""
    if not PROXY:
        return str(host), int(port)
    import socket
    import threading
    ph, _, pp = PROXY.split("//", 1)[-1].rstrip("/").partition(":")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def relay(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def serve():
        while True:
            c, _ = srv.accept()
            try:
                u = socket.create_connection((ph, int(pp or 3128)), 20)
                u.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = u.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                head, _, extra = resp.partition(b"\r\n\r\n")
                status = head.split(b"\r\n")[0].decode(errors="replace")
                if " 200 " not in status:
                    print(f"svc: egress gateway: {status}", file=sys.stderr)
                    c.close()
                    continue
                if extra:
                    c.sendall(extra)
            except OSError as e:
                print(f"svc: egress gateway not reachable: {e}", file=sys.stderr)
                c.close()
                continue
            threading.Thread(target=relay, args=(c, u), daemon=True).start()
            threading.Thread(target=relay, args=(u, c), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return "127.0.0.1", srv.getsockname()[1]


def _shm_file(content):
    """0600 file on tmpfs for secrets, readable by tcrun only (the client tool) – caller deletes it"""
    with tempfile.NamedTemporaryFile("w", dir="/dev/shm", delete=False) as fh:
        fh.write(content)
    give(fh.name, RUN_USER)
    return fh.name


def write_as_claude(path, text):
    """write a file in Claude's area as Claude (root never opens paths Claude controls – symlinks can't redirect it)"""
    return subprocess.run(["sh", "-c", 'mkdir -p "$(dirname "$1")" && cat > "$1.tmp" && mv -f "$1.tmp" "$1"', "sh", path],
                          input=text, text=True, capture_output=True, **as_user(CLAUDE_USER, cwd="/"))


def claude_home():
    pw = _account(CLAUDE_USER) if privileged() else None
    return pw.pw_dir if pw else os.path.expanduser("~")
