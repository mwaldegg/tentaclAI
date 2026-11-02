"""Notifications: channels (Apprise URLs, secrets in .env), which event goes to which channel, quiet hours, dedupe.

Config (no secrets) in data/control/notifications.json; each channel's URL lives in .env as NOTIFY_URL_<ID>.
emit() is cheap and never raises – delivery runs in a background worker.
"""
import asyncio
import os
import re
import time

from . import jsonstore
from .central import check_write, locked
from .config import DATA_DIR
from .envfile import read_env, update_env
from .log import get

log = get("notify")

CONFIG = os.path.join(DATA_DIR, "notifications.json")

# event id → (label, priority, description) – priority "high" passes quiet hours
EVENTS = {
    "approval":   ("Approval needed", "high", "a write of a confirm service or an unknown network destination waits for you"),
    "expired":    ("Approval expired", "normal", "nobody decided within 10 minutes – the action was not run"),
    "audit":      ("Audit log not writable", "high", "a write was not run because the audit log could not record it"),
    "learned":    ("Network learning over", "normal", "the learning phase ended – enforce is on, new destinations need your approval"),
    "blocked":    ("Blocked", "normal", "a write on a read-only service, a blocklisted destination or an IP target was refused"),
    "rc_down":    ("Remote Control down", "high", "remote control has not been connected for 3 minutes"),
    "logged_out": ("Claude signed out", "high", "the sandbox is no longer signed in to Claude"),
    "container":  ("Container stopped", "high", "the sandbox or the egress gateway is not running"),
    "update":     ("Update available", "low", "a new tentaclAI release is out"),
    "quota":      ("Quota running low", "normal", "the Claude session or weekly limit passed 80 % or was reached – once per window"),
    "signin":     ("Sign-in with a recovery code", "high", "someone signed in to tentacontrol with a 2FA recovery code"),
    "injection":  ("Possible prompt injection", "normal", "content from a service or a tool result looks like it tries to instruct Claude"),
    "job_result": ("Job finding", "normal", "a scheduled Claude job reported something (by its notification rule)"),
    "job_failed": ("Job failed", "normal", "a scheduled Claude job failed or ran out of time"),
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}\Z")

_queue = None
_last = {}          # dedupe key → time sent
RECENT = []         # last deliveries for the UI


def load():
    c = jsonstore.load(CONFIG)
    c.setdefault("channels", [])
    c.setdefault("routes", {})
    for ev in EVENTS:  # an event added in a later version goes where approvals go until it is set itself
        c["routes"].setdefault(ev, list(c["routes"].get("approval", [])))
    c.setdefault("quiet", {"enabled": False, "from": "23:00", "to": "07:00"})
    c.setdefault("dedupe_min", 10)
    return c


def save(c):
    jsonstore.save(CONFIG, c)


def control_link(path):
    base = (read_env().get("CONTROL_URL") or "").strip().rstrip("/")
    return base + path if base else ""


def env_key(cid):
    return "NOTIFY_URL_" + cid.upper().replace("-", "_")


def channel_url(cid):
    return read_env().get(env_key(cid), "")


def build_url(kind, f):
    """Apprise URL from the form of a preset"""
    if kind == "ntfy":
        server = (f.get("server") or "https://ntfy.sh").strip().rstrip("/")
        topic = (f.get("topic") or "").strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,64}\Z", topic):
            raise ValueError("topic: letters, digits, _ and -")
        m = re.match(r"^(https?)://([^/]+)\Z", server)
        if not m:
            raise ValueError("server: https://host[:port]")
        scheme = "ntfys" if m.group(1) == "https" else "ntfy"
        token = (f.get("token") or "").strip()
        auth = f"{token}@" if token else ""
        return f"{scheme}://{auth}{m.group(2)}/{topic}"
    if kind == "webhook":
        url = (f.get("url") or "").strip()
        m = re.match(r"^(https?)://(.+)\Z", url)
        if not m:
            raise ValueError("URL: https://…")
        scheme = "jsons" if m.group(1) == "https" else "json"
        header = (f.get("header") or "").strip()
        q = ""
        if header:
            name, _, value = header.partition(":")
            if not name.strip() or not value.strip():
                raise ValueError("header: Name: value")
            from urllib.parse import quote
            q = ("&" if "?" in m.group(2) else "?") + f"+{quote(name.strip())}={quote(value.strip())}"
        return f"{scheme}://{m.group(2)}{q}"
    if kind == "email":
        return email_url(f)
    url = (f.get("apprise") or "").strip()
    if not re.match(r"^[a-z0-9]+://", url):
        raise ValueError("an Apprise URL, e.g. tgram://bottoken/chatid")
    return url


EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+\Z")
SECURITY = {"starttls": 587, "ssl": 465, "none": 25}


def email_url(f):
    """Apprise mailto(s) URL: server, port, security (starttls / ssl / none), sender, recipients, optional login"""
    from urllib.parse import quote
    host = (f.get("host") or "").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\Z", host):
        raise ValueError("server: a host name, e.g. smtp.example.com")
    sec = f.get("security") or "starttls"
    if sec not in SECURITY:
        raise ValueError("security: starttls, ssl or none")
    try:
        port = int(f.get("port") or SECURITY[sec])
    except ValueError:
        raise ValueError("port: a number")
    if not 1 <= port <= 65535:
        raise ValueError("port: 1–65535")
    sender = (f.get("sender") or "").strip()
    to = [x.strip() for x in re.split(r"[,;\s]+", f.get("to") or "") if x.strip()]
    if not EMAIL_RE.match(sender):
        raise ValueError("from: an e-mail address")
    if not to or not all(EMAIL_RE.match(x) for x in to):
        raise ValueError("to: one or more e-mail addresses")
    user, pw = (f.get("user") or "").strip(), f.get("password") or ""
    auth = f"{quote(user, safe='')}:{quote(pw, safe='')}@" if user else ""
    q = f"from={quote(sender, safe='@')}&to={quote(','.join(to), safe='@,')}"
    if sec == "none":
        return f"mailto://{auth}{host}:{port}?{q}"
    return f"mailtos://{auth}{host}:{port}?{q}&mode={sec}"


def email_parts(url, secret=False):
    """fields of an e-mail channel URL for the edit form – the password only with secret=True (never to the browser)"""
    from urllib.parse import parse_qs, unquote, urlsplit
    if not re.match(r"^mailtos?://", url or ""):
        return {}
    u = urlsplit(url)
    q = parse_qs(u.query)
    sec = q.get("mode", ["starttls" if u.scheme == "mailtos" else "none"])[0]
    out = {"host": u.hostname or "", "port": str(u.port or SECURITY.get(sec, 587)), "security": sec,
           "sender": q.get("from", [""])[0], "to": ", ".join(q.get("to", [""])[0].split(",")), "user": unquote(u.username or "")}
    if secret:
        out["password"] = unquote(u.password or "")
    return out


def add_channel(kind, name, form):
    c = load()
    cid = re.sub(r"[^a-z0-9-]+", "-", (name or kind).lower()).strip("-")[:30] or kind
    if not ID_RE.match(cid):
        raise ValueError("name: letters and digits")
    base, n = cid, 2
    while any(ch["id"] == cid for ch in c["channels"]):
        cid, n = f"{base}-{n}", n + 1
    url = build_url(kind, form)
    update_env({env_key(cid): url})
    c["channels"].append({"id": cid, "name": name or cid, "kind": kind, "enabled": True})
    for ev in () if locked("notifications", "rules") else ("approval", "rc_down", "logged_out", "container"):
        c["routes"].setdefault(ev, [])  # sensible defaults for a new channel – unless the central server sets the routes
        if cid not in c["routes"][ev]:
            c["routes"][ev].append(cid)
    save(c)
    return cid


def public_parts(cid):
    """non-secret parts of a channel URL for the edit form (ntfy server/topic, e-mail fields) – never a token or password"""
    import re as _re
    if channel_url(cid).startswith("mailto"):
        return email_parts(channel_url(cid))
    m = _re.match(r"^(ntfys?)://(?:[^@/]*@)?([^/]+)/([^/?]+)", channel_url(cid))
    if m:
        return {"server": ("https://" if m.group(1) == "ntfys" else "http://") + m.group(2), "topic": m.group(3)}
    return {}


def update_channel(cid, name, enabled, form):
    """rename / enable; new URL only when connection fields were filled in"""
    c = load()
    ch = next((x for x in c["channels"] if x["id"] == cid), None)
    if ch is None:
        raise ValueError("unknown channel")
    new_name = (name or ch["name"]).strip()[:30] or ch["name"]
    if new_name != ch["name"]:  # the server manages id, name and kind – URL and on/off stay local
        check_write("notifications", f"channel:{cid}")
    ch["name"] = new_name
    ch["enabled"] = bool(enabled)
    fields = {"ntfy": ("token",), "webhook": ("url", "header"), "apprise": ("apprise",)}.get(ch["kind"], ())
    old = public_parts(cid) if ch["kind"] == "ntfy" else {}
    changed_ntfy = ch["kind"] == "ntfy" and any((form.get(k) or "").strip() and (form.get(k) or "").strip() != old.get(k, "")
                                               for k in ("server", "topic"))
    if ch["kind"] == "email":
        old = email_parts(channel_url(cid), secret=True)
        new = dict(old, **{k: v for k, v in form.items() if k in old and (v or "").strip()})
        if new != old:
            update_env({env_key(cid): email_url(new)})
        save(c)
        return
    if any((form.get(k) or "").strip() for k in fields) or changed_ntfy:
        merged = dict(old, **{k: v for k, v in form.items() if (v or "").strip()})
        update_env({env_key(cid): build_url(ch["kind"], merged)})
    save(c)


def remove_channel(cid):
    check_write("notifications", f"channel:{cid}")
    c = load()
    c["channels"] = [ch for ch in c["channels"] if ch["id"] != cid]
    for ev in c["routes"]:
        c["routes"][ev] = [x for x in c["routes"][ev] if x != cid]
    save(c)
    update_env({env_key(cid): ""})


def set_routes(routes, quiet, dedupe_min):
    check_write("notifications", "rules")
    c = load()
    ids = {ch["id"] for ch in c["channels"]}
    c["routes"] = {ev: [x for x in routes.get(ev, []) if x in ids] for ev in EVENTS}
    c["quiet"] = quiet
    c["dedupe_min"] = max(0, min(int(dedupe_min or 0), 1440))
    save(c)


def _quiet_now(q):
    if not q.get("enabled"):
        return False
    now = time.strftime("%H:%M")
    a, b = q.get("from", "23:00"), q.get("to", "07:00")
    return (a <= now < b) if a <= b else (now >= a or now < b)


def emit(event, title, body="", key=None, link=""):
    """queue a notification for every channel routed to this event (deduped, quiet hours respected)"""
    try:
        c = load()
        targets = [ch for ch in c["channels"] if ch.get("enabled", True) and ch["id"] in c["routes"].get(event, [])]
        if not targets or _queue is None:
            return
        prio = EVENTS.get(event, ("", "normal", ""))[1]
        if prio != "high" and _quiet_now(c["quiet"]):
            return
        k = key or f"{event}:{title}"
        if time.time() - _last.get(k, 0) < c.get("dedupe_min", 10) * 60:
            return
        _last[k] = time.time()
        _queue.put_nowait((event, prio, title, body + (f"\n{link}" if link else ""), [ch["id"] for ch in targets]))
    except Exception as e:  # noqa: BLE001 – a notification must never break the caller
        log.warning(f"notify: {e}")


def send_now(cid, title, body, prio="normal"):
    """deliver synchronously to one channel – (ok, error)"""
    import apprise
    url = channel_url(cid)
    if not url:
        return False, "no URL in .env"
    a = apprise.Apprise()
    if not a.add(url):
        return False, "invalid Apprise URL"
    ntype = {"high": apprise.NotifyType.WARNING, "low": apprise.NotifyType.INFO}.get(prio, apprise.NotifyType.INFO)
    ok = a.notify(title=title, body=body, notify_type=ntype)
    return bool(ok), "" if ok else "delivery failed (see tentacontrol logs)"


async def worker():
    global _queue
    _queue = asyncio.Queue(maxsize=500)
    while True:
        event, prio, title, body, cids = await _queue.get()
        for cid in cids:
            ok, err = await asyncio.to_thread(send_now, cid, title, body, prio)
            RECENT.insert(0, {"ts": time.time(), "event": event, "channel": cid, "title": title, "ok": ok, "error": err})
            del RECENT[50:]
