#!/usr/bin/env python3
"""tentaclAI egress gateway – the only way out of the sandbox network.

Forward proxy for CONNECT (any TCP port – HTTPS, ssh, databases; TLS is not opened) and plain HTTP requests.
Policy (from tentacontrol, refreshed every 15 s): built-in list → blocklist → own allowlist → tentacles → grants →
EGRESS_MODE permissive (allow, record as "unlisted") or enforce (hold the connection and ask in Approvals).
Every destination is counted in $DATA_DIR/egress-seen.json (host:port → first, last, count, last decision) and – except
the built-in list – reported to tentacontrol's audit log, one entry per destination and 15 minutes (refused ones at once).
"""
import asyncio
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, "/app")
import tclib  # noqa: E402

LISTEN = int(os.environ.get("EGRESS_PORT", "3128"))
CONTROL = os.environ.get("TC_CONTROL_INTERNAL", "http://tentacontrol:8080")
DATA = os.environ.get("DATA_DIR", "/data")
REFRESH = float(os.environ.get("EGRESS_REFRESH", "15"))  # seconds between policy fetches (the tests use 1)
SEEN_FILE = os.path.join(DATA, "egress-seen.json")
POLICY_CACHE = os.path.join(DATA, "policy.json")  # last policy from tentacontrol – decisions work right after a restart
DEFAULT = tclib.egress_patterns(open(os.environ.get("EGRESS_DEFAULT_LIST", "/app/egress-default.txt")).read())
IDLE = 3600  # seconds a tunnel may stay silent (ssh sessions, long polls)
HOLD = 60  # seconds an unknown destination waits for the user's decision (enforce)

seen, dirty, cleared = {}, False, 0.0
pol = {"mode": os.environ.get("EGRESS_MODE", "permissive"), "direct_ip": "block", "allow": [], "block": [], "tentacles": {},
       "grants": {}, "ok": False}


def control(path, payload=None, timeout=30):
    req = urllib.request.Request(CONTROL + path, data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"Content-Type": "application/json"}, method="POST" if payload is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


FAIL_LOG_AFTER = 3  # failed fetches in a row before the log says so (with REFRESH 15: ~45 s)
failing = {"n": 0, "since": 0}


def refresh(p=None):
    """policy from tentacontrol (cached on disk); keeps the last known one when tentacontrol is unreachable"""
    if p is None:
        try:
            p = control("/internal/egress/policy", timeout=10)
        except Exception as e:  # noqa: BLE001
            # a restart of tentacontrol takes a few seconds – only a longer outage is worth a line
            failing["n"] += 1
            failing["since"] = failing["since"] or time.time()
            if pol["ok"] and failing["n"] == FAIL_LOG_AFTER:
                print(f"policy refresh failing since {time.strftime('%H:%M:%S', time.localtime(failing['since']))} – "
                      f"keeping the last policy: {e}", flush=True)
            return
        if failing["n"] >= FAIL_LOG_AFTER:
            print(f"policy refresh works again after {round(time.time() - failing['since'])} s", flush=True)
        failing.update(n=0, since=0)
        try:
            with open(POLICY_CACHE + ".tmp", "w") as f:
                json.dump(p, f)
            os.replace(POLICY_CACHE + ".tmp", POLICY_CACHE)
        except OSError:
            pass
    global seen, dirty, cleared
    if p.get("cleared", 0) > cleared:  # "Clear" on the Network page
        seen, dirty = {k: v for k, v in seen.items() if v.get("last", 0) > p["cleared"]}, True
        cleared = p["cleared"]
    pol.update(mode=p.get("mode", "permissive"), direct_ip=p.get("direct_ip", "block"), allow=p.get("allow", []), block=p.get("block", []), ok=True,
               tentacles={(h, pt): n for h, pt, n in p.get("tentacles", [])}, grants=dict(p.get("grants", {})))


async def refresher():
    while True:
        await asyncio.to_thread(refresh)
        await asyncio.sleep(REFRESH if pol["ok"] else 2)  # retry quickly until the first policy arrived


async def policy_ready(seconds=30):
    """no policy yet (first start, tentacontrol still starting): wait for it instead of deciding without rules"""
    end = time.time() + seconds
    while not pol["ok"] and time.time() < end:
        await asyncio.sleep(0.5)
    return pol["ok"]


def decide(host, port, ips):
    """(allow?, reason) – the rule order lives in tclib.egress_rule (shared with tentacontrol's Network page)"""
    kind, _ = tclib.egress_rule(host, port, ips, DEFAULT, pol["block"], pol["allow"], pol["tentacles"], pol["grants"])
    if kind in ("default", "allow"):
        return True, "allowlist"
    if kind == "blocked":
        return False, "blocked"
    if kind in ("tentacle", "grant"):
        return True, kind
    if pol["mode"] != "enforce":
        return True, "unlisted"
    if tclib.is_ip(host) and pol["direct_ip"] == "block":
        return False, "direct-ip"
    return None, "ask"


_control = [0.0, set()]  # ts, addresses of tentacontrol


def control_addrs():
    """tentacontrol's own addresses: never a destination – its /internal/egress endpoints trust the gateway"""
    if time.time() - _control[0] > 30 or not _control[1]:
        try:
            name = urllib.parse.urlsplit(CONTROL).hostname or ""
            _control[:] = [time.time(), {i[4][0] for i in socket.getaddrinfo(name, None)}]
        except (OSError, ValueError):
            pass
    return _control[1]


def _plain(a):
    """an address in one spelling – ::ffff:10.0.0.1 is 10.0.0.1"""
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return None
    return getattr(ip, "ipv4_mapped", None) or ip


def own_target(ips):
    """a connection back to tentacontrol or into the gateway itself (loopback)"""
    control = {_plain(a) for a in control_addrs()}
    return any(ip is not None and (ip.is_loopback or ip in control) for ip in map(_plain, ips))


async def resolve(host, port):
    """addresses the gateway will connect to – checked against IP/CIDR rules, then used for the connection (no re-resolve)"""
    if tclib.is_ip(host):
        return [host]
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):  # a.b..c or a label idna can't encode
        return []
    return sorted(dict.fromkeys(i[4][0] for i in infos), key=lambda a: ":" in a)  # IPv4 first


async def ask(host, port, client_port=0):
    """enforce: request an approval in tentacontrol and hold the connection up to HOLD seconds (client_port: the
    sandbox's end of this connection – tentacontrol looks up which process holds it while it is held)"""
    try:
        rid = (await asyncio.to_thread(control, "/internal/egress/ask", {"host": host, "port": port, "client_port": client_port}))["id"]
        end = time.time() + HOLD
        while time.time() < end:
            st = await asyncio.to_thread(control, f"/internal/egress/wait/{rid}?wait=20", None, 30)
            if st.get("status") != "pending":
                await asyncio.to_thread(refresh)
                return st.get("status") == "approved"
    except Exception as e:  # noqa: BLE001
        print(f"approval for {host}:{port} failed: {e}", flush=True)
    return False


def report(host, port, reason):
    """tell tentacontrol about a refused destination (notifications) – best effort"""
    try:
        control("/internal/egress/event", {"host": host, "port": port, "reason": reason}, timeout=5)
    except Exception:  # noqa: BLE001
        pass


def load_seen():
    global seen
    try:
        seen = json.load(open(SEEN_FILE))
    except (OSError, ValueError):
        seen = {}


def record(host, port, decision):
    global dirty
    now = int(time.time())
    e = seen.setdefault(f"{host}:{port}", {"first": now, "count": 0})
    e.update(last=now, count=e["count"] + 1, decision=decision)
    dirty = True


AUDIT_WINDOW = 900  # s: allowed connections to one destination become one audit entry per 15 min (with a count)
AUDIT_MAX = 1000  # destinations kept while tentacontrol can't be reached
audit_buf = {}  # (host, port, decision, reason) → {"count", "first", "last"}


def audit_note(host, port, why):
    """count a connection for the audit log – built-in destinations (Claude's API, package mirrors) only show on the
    Network page; approved/denied ones are logged by tentacontrol when the user decides"""
    if why in ("approved", "denied") or any(tclib.egress_match(p, host, port) for p in DEFAULT):
        return
    now = int(time.time())
    key = (host, port, "blocked" if why in ("blocked", "direct-ip") else "allowed", why)
    if key not in audit_buf and len(audit_buf) >= AUDIT_MAX:
        return
    e = audit_buf.setdefault(key, {"count": 0, "first": now})
    e.update(count=e["count"] + 1, last=now)


def audit_due(now=None):
    """the entries to send now: refused destinations at once (next flush), allowed ones once their window is over"""
    now = now or time.time()
    return [k for k, e in audit_buf.items() if k[2] == "blocked" or now - e["first"] >= AUDIT_WINDOW]


async def audit_flush():
    while True:
        await asyncio.sleep(30)
        due = audit_due()
        if not due:
            continue
        batch = [{"host": k[0], "port": k[1], "decision": k[2], "reason": k[3], **audit_buf[k]} for k in due]
        try:
            await asyncio.to_thread(control, "/internal/egress/audit", {"entries": batch}, 10)
        except Exception as e:  # noqa: BLE001 – kept and sent with the next flush
            print(f"audit report failed: {e}", flush=True)
            continue
        for k in due:
            audit_buf.pop(k, None)


SEEN_MAX, SEEN_DAYS = 2000, 90  # the list of destinations stays small – the gateway has 128 MB


def prune(entries, now=None):
    """drop destinations unused for SEEN_DAYS, then keep the SEEN_MAX most recent"""
    cutoff = (now or time.time()) - SEEN_DAYS * 86400
    keep = {k: v for k, v in entries.items() if v.get("last", 0) >= cutoff}
    if len(keep) > SEEN_MAX:
        keep = dict(sorted(keep.items(), key=lambda kv: -kv[1].get("last", 0))[:SEEN_MAX])
    return keep


async def flush():
    global dirty, seen
    while True:
        await asyncio.sleep(10)
        if dirty:
            dirty = False
            seen = prune(seen)
            with open(SEEN_FILE + ".tmp", "w") as f:
                json.dump(seen, f, indent=1, sort_keys=True)
            os.replace(SEEN_FILE + ".tmp", SEEN_FILE)


# an address in a short or numeric form (127.1, 2130706433, 0x7f.0.0.1): getaddrinfo takes it as an IP, the rules
# would see a name – refused, it has to be written out
NUMERIC_HOST = re.compile(r"(0x[0-9a-f]*|\d+)(\.(0x[0-9a-f]*|\d+)){0,3}\.?")


def split_hostport(s, default):
    """(host, port) of host:port or [v6]:port – ValueError for a port outside 1–65535 or an address in short form"""
    s = s.strip()
    if s.startswith("["):  # [v6]:port
        h, _, rest = s[1:].partition("]")
        host, port = h.lower(), int(rest[1:] or default)
    else:
        h, _, p = s.rpartition(":") if s.count(":") == 1 else (s, "", "")
        host, port = h.lower().rstrip("."), int(p or default)
    if not 0 < port < 65536 or not host:
        raise ValueError("bad port")
    if NUMERIC_HOST.fullmatch(host) and not tclib.is_ip(host):
        raise ValueError("an IP address in short form")
    return host, port


async def pipe(r, w):
    try:
        while True:
            data = await asyncio.wait_for(r.read(65536), IDLE)
            if not data:
                break
            w.write(data)
            await w.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            w.close()
        except OSError:
            pass


def refuse(cw, code, text):
    cw.write(f"HTTP/1.1 {code}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n{text}\n".encode())
    cw.close()


async def handle(cr, cw):
    """one client connection – closed in the end whatever happens on the way"""
    try:
        await _handle(cr, cw)
    except Exception as e:  # noqa: BLE001 – never leave the client hanging on an unexpected error
        print(f"connection error: {type(e).__name__}: {e}", flush=True)
    finally:
        try:
            cw.close()
        except OSError:
            pass


async def _handle(cr, cw):
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 30)
        method, target, version = head.decode("latin-1").split("\r\n")[0].split(" ", 2)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError):
        cw.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    try:
        if method.upper() == "CONNECT":
            host, port = split_hostport(target, 443)
            rest = b""
        elif target.startswith("http://"):  # plain HTTP: absolute URI → origin form, one request per connection
            hostpart, _, path = target[7:].partition("/")
            host, port = split_hostport(hostpart, 80)
            hdrs = [l for l in lines[1:] if l and not l.lower().startswith(("proxy-", "connection:", "keep-alive:"))]
            rest = (f"{method} /{path} {version}\r\n" + "\r\n".join(hdrs) + "\r\nConnection: close\r\n\r\n").encode("latin-1")
        else:
            return refuse(cw, "400 Bad Request", "tentaclAI egress: proxy requests only")
    except ValueError:
        return refuse(cw, "400 Bad Request", "tentaclAI egress: bad host or port")
    ips = await resolve(host, port)
    if not await policy_ready():
        return refuse(cw, "503 Service Unavailable", "tentaclAI egress: no rules from tentacontrol yet – try again in a moment")
    if own_target(ips):
        return refuse(cw, "403 Forbidden", f"tentaclAI egress: {host}:{port} is tentacontrol or the gateway itself – not a destination")
    ok, why = decide(host, port, ips)
    if ok is None:  # the cached policy may predate a service enabled or a token set just now – check fresh first
        await asyncio.to_thread(refresh)
        ok, why = decide(host, port, ips)
    if ok is None:
        peer = cw.get_extra_info("peername")
        ok = await ask(host, port, peer[1] if isinstance(peer, tuple) and len(peer) > 1 else 0)
        why = "approved" if ok else "denied"
    record(host, port, why)
    audit_note(host, port, why)
    if not ok and why in ("blocked", "direct-ip", "denied"):
        asyncio.get_running_loop().run_in_executor(None, report, host, port, why)
    if not ok:
        return refuse(cw, "403 Forbidden", f"tentaclAI egress: {host}:{port} is {why} – allow it in tentacontrol → Network or approve it in Approvals")
    if not ips:
        return refuse(cw, "502 Bad Gateway", f"{host}: name not found")
    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection(ips[0], port), 20)
    except (OSError, asyncio.TimeoutError) as e:
        return refuse(cw, "502 Bad Gateway", f"{host}:{port}: {e}")
    if method.upper() == "CONNECT":
        cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await cw.drain()
    else:
        uw.write(rest)
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))


async def main():
    os.makedirs(DATA, exist_ok=True)
    load_seen()
    try:
        refresh(json.load(open(POLICY_CACHE)))
    except (OSError, ValueError):
        pass
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN, limit=65536)
    print(f"tentaclAI egress gateway on :{LISTEN}", flush=True)
    asyncio.create_task(flush())
    asyncio.create_task(audit_flush())
    asyncio.create_task(refresher())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
