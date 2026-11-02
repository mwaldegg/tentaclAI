"""MCP: the servers handed to Claude Code, and svc's proxy in front of each – stdio servers as a child process, http
servers bridged (stdio ↔ Streamable HTTP) with the credentials injected; every tool call goes through the access gate."""
import fnmatch
import json
import os
import re
import subprocess
import sys
import threading
import time

from . import core, gate, safeguards


# ---------- MCP ----------
# Every MCP server is registered in Claude's config as `svc mcp-proxy <name>`: the tokens never land in Claude's
# ~/.claude.json, and svc sees each JSON-RPC message. tools/list tells which tools only read (the server's readOnlyHint,
# or read_tools / write_tools in the service file); a tools/call of any other tool is a write: blocked with access
# read, logged with write, approved first with confirm (guarded() – the same gate as every other write).

TOOLS_DIR = os.path.join(core.TC_DIR, "data", "control", "mcp-tools")  # the last tools/list per service – tentacontrol shows it


def claude_mcp(*args):
    return subprocess.run(["claude", "mcp", *args], capture_output=True, text=True, **core.as_user(core.CLAUDE_USER, cwd="/"))


def mcp_entry(name, mcp):
    """what Claude's config gets: always the svc proxy – it holds the secrets and gates the tool calls"""
    return {"type": "stdio", "command": "svc", "args": ["mcp-proxy", name]}


def _patterns(m, key):
    v = m.get(key)
    return [str(x) for x in v if isinstance(x, str) and x.strip()] if isinstance(v, list) else []


def tool_kind(m, name, annotations=None):
    """read | write | destructive – write_tools and read_tools of the service file first, then the server's hints
    (readOnlyHint true: read; destructiveHint true: destructive). A tool the server doesn't mark is a write"""
    if any(fnmatch.fnmatchcase(name, p) for p in _patterns(m, "write_tools")):
        return "destructive" if (annotations or {}).get("destructiveHint") is True else "write"
    if any(fnmatch.fnmatchcase(name, p) for p in _patterns(m, "read_tools")):
        return "read"
    a = annotations if isinstance(annotations, dict) else {}
    if a.get("readOnlyHint") is True:
        return "read"
    return "destructive" if a.get("destructiveHint") is True else "write"


def call_action(tool, args):
    """the audit and approval text of a tool call: name and arguments (sorted – the same call gives the same text, so
    an approval handed back is found again), secrets blanked"""
    a = json.dumps(args if isinstance(args, dict) else {}, ensure_ascii=False, sort_keys=True, separators=(", ", ": "))
    return safeguards._redact_text(f"{tool} {a}")[:500]


def _result(rid, text, error=True):
    return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}], "isError": error}}


def _error_text(msg):
    """the start of a failed call's message for the audit log"""
    if isinstance(msg.get("error"), dict):
        return str(msg["error"].get("message", ""))[:300]
    content = (msg.get("result") or {}).get("content") or []
    text = " ".join(str(c.get("text", "")) for c in content if isinstance(c, dict) and c.get("type") == "text")
    return safeguards._redact_text(re.sub(r"\s+", " ", text).strip())[:300]


class ToolGate:
    """the access gate between Claude and one MCP server: request() for every message from Claude (None: pass it on,
    else the answer instead – may wait for an approval), response() for every message from the server"""

    def __init__(self, name, m):
        self.name, self.m = name, m
        self.mode = gate.access_mode(m, "read")
        self.hints = self._load()  # tool → the server's hints (readOnlyHint, destructiveHint)
        self.methods = {}  # request id → (method, a further page of a listing), for the answers
        self.listed = []  # the tools of this listing so far (tools/list can come in pages)
        self.calls = {}  # request id → (admitted write or None for a read, action, start time)
        self.lock = threading.Lock()

    def _path(self):
        return os.path.join(TOOLS_DIR, f"{self.name}.json")

    def _load(self):
        """the hints seen in an earlier session – a tools/call before this session's tools/list still knows them"""
        try:
            with open(self._path()) as f:
                return {t["name"]: t.get("hints") or {} for t in json.load(f).get("tools", []) if isinstance(t, dict) and "name" in t}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return {}

    def _save(self, tools):
        doc = {"at": int(time.time()), "tools": tools}
        try:
            os.makedirs(TOOLS_DIR, mode=0o755, exist_ok=True)
            tmp = self._path() + f".{os.getpid()}.tmp"
            with open(tmp, "w") as f:
                json.dump(doc, f, indent=1)
            os.chmod(tmp, 0o644)
            os.replace(tmp, self._path())
        except OSError:
            pass

    def kind(self, tool):
        return tool_kind(self.m, tool, self.hints.get(tool))

    def request(self, msg):
        rid, method = msg.get("id"), msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if rid is not None and method:
            with self.lock:
                self.methods[json.dumps(rid)] = (method, bool(params.get("cursor")))
        if method != "tools/call":
            return None
        if rid is None:  # a notification gets no answer – a server that runs it anyway would bypass the gate
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "MCP proxy: tools/call needs an id"}}
        tool = str(params.get("name", ""))[:200]
        action = call_action(tool, params.get("arguments"))
        kind = self.kind(tool)
        if kind == "read":
            with self.lock:
                self.calls[json.dumps(rid)] = (None, action, time.time())
            return None
        review = {"risks": ["destructive tool – the server marks it so"]} if kind == "destructive" else None
        try:
            ctx = gate.admit(self.name, "mcp", self.mode, action, review=review)
        except gate.Stop as e:
            with self.lock:
                self.methods.pop(json.dumps(rid), None)
            if e.link:
                return _result(rid, f"⏸ svc: approval still pending – the user approves it at {e.link}\nGive the user this "
                                    "link in one line now, then call the same tool with exactly the same arguments again: "
                                    "it waits for the same request.")
            return _result(rid, e.message)
        with self.lock:
            self.calls[json.dumps(rid)] = (ctx, action, time.time())
        return None

    def response(self, msg):
        if not isinstance(msg, dict) or msg.get("method") or "id" not in msg:
            return msg  # notifications and the server's own requests
        key = json.dumps(msg.get("id"))
        with self.lock:
            method, more = self.methods.pop(key, (None, False))
            call = self.calls.pop(key, None)
        if method == "tools/list" and isinstance(msg.get("result"), dict) and isinstance(msg["result"].get("tools"), list):
            return self._listed(msg, more)
        if call:
            ctx, action, t = call
            failed = "error" in msg or bool((msg.get("result") or {}).get("isError"))
            if ctx:
                gate.finish(ctx, 1 if failed else 0, time.time() - t, _error_text(msg) if failed else "")
            else:
                gate.audit(self.name, "mcp", self.mode, action, "read", rc=1 if failed else 0, duration=time.time() - t)
        return msg

    def _listed(self, msg, more=False):
        """note each tool's kind (more: a further page of the same listing); with access read only the reading tools
        are offered"""
        seen, keep = [], []
        for t in msg["result"]["tools"]:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                continue
            a = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
            hints = {h: True for h in ("readOnlyHint", "destructiveHint") if a.get(h) is True}
            self.hints[t["name"]] = hints
            k = tool_kind(self.m, t["name"], hints)
            seen.append({"name": t["name"][:200], "kind": k, "hints": hints,
                         "title": str(t.get("title") or t.get("description") or "").strip().split("\n")[0][:160]})
            if self.mode != "read" or k == "read":
                keep.append(t)
        self.listed = (self.listed if more else []) + seen
        self._save(sorted(self.listed, key=lambda t: t["name"]))
        return {**msg, "result": {**msg["result"], "tools": keep}}


def cmd_mcp_proxy(services, name):
    svc = services.get(name) or sys.exit(f"svc: unknown service '{name}'")
    if "mcp" not in svc or not core.enabled(svc) or core.missing_vars(svc["mcp"]):
        sys.exit(f"svc: {name}: MCP not available (svc test {name})")
    gate.require_allowed(name)
    m = core.render(svc["mcp"])
    kind = m.get("type", "stdio" if m.get("command") else "http")
    if kind == "stdio":
        return mcp_stdio(m, ToolGate(name, m))
    if kind != "http":
        sys.exit(f"svc: {name}: MCP type {kind} can't be proxied – use type http (Streamable HTTP)")
    return mcp_bridge(m, ToolGate(name, m))


def _emitter():
    lock = threading.Lock()

    def emit(obj):
        with lock:
            sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return emit


def _messages(stream):
    """(line, message) for each JSON-RPC object on stdin"""
    for line in stream:
        line = line.strip()
        try:
            msg = json.loads(line) if line else None
        except ValueError:
            continue
        if isinstance(msg, dict):
            yield line, msg


def mcp_stdio(m, tg):
    """a stdio server as the service's user with its env, svc in between: Claude's lines go to the server after the
    gate, the server's lines come back through it"""
    kw = core.runner(tg.name, {k: str(v) for k, v in (m.get("env") or {}).items()})
    pw = core.run_account(tg.name)
    kw["cwd"] = pw.pw_dir if pw else core.ORIG_CWD
    try:
        p = subprocess.Popen([m["command"], *[str(a) for a in m.get("args", [])]], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True, bufsize=1, **kw)
    except OSError as e:
        sys.exit(f"svc: MCP server {m.get('command')} can't be started: {e}")
    emit, wlock = _emitter(), threading.Lock()

    def to_server(line):
        with wlock:
            try:
                p.stdin.write(line + "\n")
                p.stdin.flush()
            except (BrokenPipeError, ValueError):
                pass

    def from_server():
        for line, msg in _messages(p.stdout):
            emit(tg.response(msg))

    def gated(line, msg):
        answer = tg.request(msg)
        if answer:
            emit(answer)
        else:
            to_server(line)
    reader = threading.Thread(target=from_server, daemon=True)
    reader.start()
    calls = []
    for line, msg in _messages(sys.stdin):
        if msg.get("method") == "tools/call":
            calls.append(threading.Thread(target=gated, args=(line, msg), daemon=True))  # an approval may take minutes
            calls[-1].start()
        else:
            gated(line, msg)
    for t in calls:  # Claude is gone – calls already admitted still reach the server, a pending approval doesn't matter
        t.join(timeout=2)
    with wlock:
        try:
            p.stdin.close()
        except OSError:
            pass
    try:
        rc = p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.terminate()
        rc = p.wait()
    reader.join(timeout=3)
    return rc


def mcp_bridge(m, tg):
    import ssl
    import urllib.error
    import urllib.request
    ctx = ssl._create_unverified_context() if m.get("insecure_tls") else ssl.create_default_context()
    headers = {str(k): str(v) for k, v in (m.get("headers") or {}).items()}
    state = {"session": None, "version": None}
    emit = _emitter()

    def out(msg):
        note_version(msg)
        emit(tg.response(msg))

    def post(line, rid):
        h = dict(headers, **{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
        if state["session"]:
            h["Mcp-Session-Id"] = state["session"]
        if state["version"]:
            h["MCP-Protocol-Version"] = state["version"]
        req = urllib.request.Request(m["url"], data=line.encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as r:
                sid = r.headers.get("Mcp-Session-Id")
                if sid:
                    state["session"] = sid
                ctype = r.headers.get("Content-Type", "")
                if r.status == 202:
                    return
                if "text/event-stream" in ctype:
                    data = []
                    for raw in r:
                        l = raw.decode("utf-8", "replace").rstrip("\r\n")
                        if l.startswith("data:"):
                            data.append(l[5:].lstrip())
                        elif not l and data:
                            msg = json.loads("\n".join(data))
                            data = []
                            out(msg)
                    if data:
                        out(json.loads("\n".join(data)))
                    return
                body = r.read().decode("utf-8", "replace").strip()
                if body:
                    msg = json.loads(body)
                    for x in (msg if isinstance(msg, list) else [msg]):
                        out(x)
        except urllib.error.HTTPError as e:
            if e.code == 404 and state["session"]:
                state["session"] = None  # session expired – the client has to initialize again
            if rid is not None:
                out({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": f"HTTP {e.code} from MCP server"}})
        except Exception as e:  # noqa: BLE001 – network errors, bad JSON
            if rid is not None:
                out({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": f"MCP proxy: {str(e)[:200]}"}})

    def gated(line, msg, rid):
        answer = tg.request(msg)
        if answer:
            emit(answer)
        else:
            post(line, rid)

    def note_version(msg):
        if isinstance(msg, dict) and isinstance(msg.get("result"), dict) and msg["result"].get("protocolVersion"):
            state["version"] = msg["result"]["protocolVersion"]

    for line, msg in _messages(sys.stdin):
        rid = msg.get("id")
        if rid is None or msg.get("method") == "initialize" or not state["session"] and not state["version"]:
            gated(line, msg, rid)  # initialize and notifications in order (initialize sets the session id)
        else:
            threading.Thread(target=gated, args=(line, msg, rid), daemon=True).start()  # requests may run long – in parallel
    return 0
