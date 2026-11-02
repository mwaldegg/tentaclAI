"""Who may talk to tentacontrol from the sandbox network.

tentacontrol sits in the sandbox network because svc (in the sandbox) asks it for approvals – which also put the admin
UI, the login and the gateway endpoints within Claude's reach. Requests are classified by their source address:
  sandbox container → only the svc endpoints (/internal/approvals…, /internal/event, /internal/jobs…; they also need the svc token)
  egress gateway    → only /internal/egress/*
  anyone else       → everything except /internal/egress/* (UI and login still need the password)
The containers are found by name in Docker's DNS, so a recreated container with a new address is recognised. Any
other address from the sandbox's own network (subnet read from Docker) also counts as the sandbox – if a lookup
fails, a request from there gets less, not more.
"""
import ipaddress
import os
import socket
import time

from . import dockerops
from .config import CLAUDE_CONTAINER

EGRESS_NAME = "egress"  # network alias of the gateway in the sandbox network
SANDBOX_PATHS = ("/internal/approvals", "/internal/event", "/internal/jobs")
_cache = {}  # name -> (ts, set of addresses)


def _resolve(name):
    ts, ips = _cache.get(name, (0.0, set()))
    if time.time() - ts < 5:
        return ips
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(name, None)}
    except OSError:
        ips = set()
    if ips:  # a miss is not cached: while the sandbox starts, its first requests would count as "anyone else"
        _cache[name] = (time.time(), ips)
    return ips


_net = [0.0, []]  # ts, subnets of the sandbox container's networks


def _sandbox_nets():
    if time.time() - _net[0] < (60 if _net[1] else 5):
        return _net[1]
    nets = []
    try:
        api = dockerops.client().api
        for name in api.inspect_container(CLAUDE_CONTAINER)["NetworkSettings"]["Networks"]:
            for cfg in api.inspect_network(name).get("IPAM", {}).get("Config") or []:
                if cfg.get("Subnet"):
                    nets.append(ipaddress.ip_network(cfg["Subnet"]))
    except Exception:  # noqa: BLE001  no Docker, no container yet – the name lookup still works
        nets = []
    _net[:] = [time.time(), nets]
    return nets


def _plain(ip):
    """one spelling per address – ::ffff:192.168.80.3 is 192.168.80.3; '' for no address"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return str(getattr(a, "ipv4_mapped", None) or a)


def _in(ip, nets):
    try:
        a = ipaddress.ip_address(_plain(ip))
    except ValueError:
        return False
    return any(a in n for n in nets)


def source(ip):
    """'sandbox', 'egress' or 'other'"""
    ip = _plain(ip or "") or ip
    if ip and ip in _resolve(CLAUDE_CONTAINER):
        return "sandbox"
    if ip and ip in _resolve(EGRESS_NAME):
        return "egress"
    if ip and _in(ip, _sandbox_nets()):
        return "sandbox"  # from the sandbox network but not recognised: treat it like the sandbox
    return "other"


def allowed(path, ip):
    kind = source(ip)
    if path.startswith("/internal/egress/"):
        return kind == "egress"
    if kind == "sandbox":
        return any(path == p or path.startswith(p + "/") for p in SANDBOX_PATHS)
    if kind == "egress":
        return False
    return True


# ---------- the client address behind a reverse proxy ----------

FORWARDED_HEADERS = (b"x-forwarded-for", b"x-forwarded-proto", b"x-forwarded-host", b"x-forwarded-port", b"x-real-ip",
                     b"forwarded")


def trusted_proxies(value=None):
    """FORWARDED_ALLOW_IPS (comma-separated addresses/CIDRs): the reverse proxies whose X-Forwarded-For counts – None
    (default, or *) means any address that is neither the sandbox nor the gateway"""
    value = os.environ.get("FORWARDED_ALLOW_IPS", "*") if value is None else value
    if value.strip() in ("", "*"):
        return None
    nets = []
    for part in value.split(","):
        try:
            nets.append(ipaddress.ip_network(part.strip(), strict=False))
        except ValueError:
            pass
    return nets


def forwarded_client(peer, xff, proxies):
    """the client behind the proxy chain: the right-most X-Forwarded-For address that is not a trusted proxy – the
    left part is whatever the client sent itself. Without a proxy list only the last hop (what the proxy saw) counts"""
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    if proxies is None:
        return hops[-1] if hops else peer
    for h in reversed(hops):
        if not _in(h, proxies):
            return h
    return hops[0] if hops else peer


class ProxyHeaders:
    """X-Forwarded-For/-Proto from a reverse proxy (instead of uvicorn's --proxy-headers, which trusted any sender):
    never from the sandbox or the gateway – they would set their own address past the checks above and the login
    throttle – and from anyone else only if FORWARDED_ALLOW_IPS lists them (default: anyone)"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            peer = (scope.get("client") or ("", 0))[0]
            headers = dict(scope["headers"])
            proxies = trusted_proxies()
            if source(peer) != "other" or proxies is not None and not _in(peer, proxies):
                scope = dict(scope, headers=[(k, v) for k, v in scope["headers"] if k not in FORWARDED_HEADERS])
            else:
                scope = dict(scope)
                if b"x-forwarded-for" in headers:
                    scope["client"] = (forwarded_client(peer, headers[b"x-forwarded-for"].decode("latin-1"), proxies), 0)
                proto = headers.get(b"x-forwarded-proto", b"").decode("latin-1").split(",")[-1].strip().lower()
                if proto in ("http", "https"):
                    scope["scheme"] = proto if scope["type"] == "http" else {"http": "ws", "https": "wss"}[proto]
        await self.app(scope, receive, send)
