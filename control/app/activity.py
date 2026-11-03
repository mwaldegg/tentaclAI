"""Approvals: pending approvals (access mode "confirm") and grants; origin labels for approvals and the audit log
(Logs → Audit, auditlog.py – network decisions are written from here, svc never sees them).

svc talks to the /internal/* endpoints with the token in data/control/svc-token. Approvals and grants are kept in
data/control/approvals.json (0600): a restart of tentacontrol keeps pending requests, decisions not used yet and grants –
svc keeps waiting through the restart, and a decision is still used only once.
"""
import asyncio
import itertools
import os
import re
import secrets
import time

import tclib

from . import auditlog, dockerops, jsonstore, notify, sshhosts, usage
from .config import DATA_DIR, SERVICES_DIR
from .log import get

log = get("approvals")

TOKEN_FILE = os.path.join(DATA_DIR, "svc-token")
STATE_FILE = os.path.join(DATA_DIR, "approvals.json")
TIMEOUT = 600
GRANT_SECONDS = 15 * 60
NO_GRANT_PARTS = ("config",)  # service files / site rules: every write is approved on its own

_ids = itertools.count(1)
BOOT = secrets.token_hex(4)  # ids start at 1 again after a restart – the browser tells the two apart by this
APPROVALS = {}  # id -> dict
GRANTS = {}  # (service, part) -> {"until": ts, "by": who} – "Approve + 15 min"
_TRANSIENT = ("event", "again", "lookup")  # not kept: the event is made anew on load, "again" is read once by the route,
# "lookup" marks a network request whose process is being looked up
CID_RE = re.compile(r"[0-9a-f]{12}")


def save():
    """approvals and grants to STATE_FILE – never raises (it carries them across a restart; deciding works without)"""
    try:
        jsonstore.save(STATE_FILE, {"next": int(max(APPROVALS, key=int, default="0")) + 1,
                                    "approvals": [{k: v for k, v in a.items() if k not in _TRANSIENT} for a in APPROVALS.values()],
                                    "grants": [{"service": s, "part": p, **g} for (s, p), g in GRANTS.items()]},
                       indent=None, mode=0o600)
    except (OSError, TypeError, ValueError) as e:
        log.warning("approvals not saved: %s", e)


def load():
    """at startup: the state of the last run – pending requests keep their age (TIMEOUT counts from their creation)"""
    global _ids
    d = jsonstore.load(STATE_FILE)
    APPROVALS.clear()
    GRANTS.clear()
    for a in d.get("approvals", []):
        if not isinstance(a, dict) or not str(a.get("id", "")).isdigit():
            continue
        a["event"] = asyncio.Event()
        if a.get("status") != "pending":
            a["event"].set()
        APPROVALS[str(a["id"])] = a
    for g in d.get("grants", []):
        if isinstance(g, dict) and g.get("until", 0) > time.time():
            GRANTS[(g.get("service", ""), g.get("part", ""))] = {"until": g["until"], "by": g.get("by", "")}
    _ids = itertools.count(max(int(d.get("next") or 1), int(max(APPROVALS, key=int, default="0")) + 1))
    _expire()


def ensure_token():
    """shared secret for svc → tentacontrol (readable in the sandbox through the stack mount)"""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE + ".tmp", "w") as f:
            f.write(secrets.token_urlsafe(32))
        os.chmod(TOKEN_FILE + ".tmp", 0o600)
        os.replace(TOKEN_FILE + ".tmp", TOKEN_FILE)


def token_ok(value):
    try:
        return bool(value) and secrets.compare_digest(value, open(TOKEN_FILE).read().strip())
    except OSError:
        return False


def audit_network(a, decision, detail=""):
    """a decided request of the egress gateway (unknown destination) – svc never sees these"""
    if a.get("part") == "network":
        auditlog.write("network", a["service"], a["action"], decision, actor="claude", mode="confirm", detail=detail,
                       approver=a.get("approver", ""), grant=a.get("grant", ""), origin=a.get("origin") or None,
                       process=a.get("process", ""), process_user=a.get("process_user", ""), requested=tclib.audit_ts(a["created"]),
                       attempts=a["attempts"] if a.get("attempts", 1) > 1 else None)


def _expire():
    now, changed = time.time(), False
    for a in APPROVALS.values():
        if a["status"] == "pending" and now - a["created"] > TIMEOUT:
            a.update(status="expired", decided=now)
            a["event"].set()
            changed = True
            audit_network(a, "expired", "no decision in time")
            notify.emit("expired", f"Approval expired: {a['service']}", a["action"], key=f"expired:{a['id']}")
    for k in [k for k, a in APPROVALS.items() if a["status"] != "pending" and now - a.get("decided", now) > 3600]:
        APPROVALS.pop(k, None)
        changed = True
    if changed:
        save()


_ORIGIN_KEYS = {"session": r"(cse_[A-Za-z0-9]{10,60}|[0-9a-f-]{36})", "entry": r"[a-z][a-z-]{0,19}", "tmux": r"[A-Za-z0-9._-]{1,40}",
                "by": r"root", "job": r"[a-z0-9]{6,40}"}


def clean_origin(o):
    """only the known keys with well-formed values – svc reports them, but Claude could have set them"""
    if not isinstance(o, dict):
        return {}
    return {k: str(v) for k, v in o.items() if k in _ORIGIN_KEYS and re.fullmatch(_ORIGIN_KEYS[k], str(v))}


def origin_label(o):
    """'Remote Control · Mailcow prüfen' – where a request came from (a hint: Claude controls these values)"""
    o = clean_origin(o)
    if not o:
        return ""
    if o.get("by") == "root":
        return "tentacontrol / host"
    if o.get("job"):  # set by svc from the job's process marker, not from Claude's variables
        from .scheduled import running_job_name
        return f"Job · {running_job_name(o['job']) or o['job']}"
    parts = []
    if o.get("tmux"):
        parts.append(dockerops.session_label(o["tmux"]))
    elif o.get("entry"):
        parts.append({"cli": "Claude terminal", "sdk-cli": "Claude (headless / Remote Control)"}.get(o["entry"], f"Claude ({o['entry']})"))
    else:
        parts.append("shell")
    if o.get("session"):
        title = (usage._local()["sessions"].get(o["session"]) or {}).get("title", "")
        parts.append(f"“{title}”" if title else o["session"][:8])
    return " · ".join(parts)


def _again(service, part, action, origin):
    """the same write of the same Claude session asked again after svc handed it back (approval_handoff): still
    pending, or decided and not used yet – a decision is used once, by the first call that sees it"""
    sid = origin.get("session")
    if not sid or part == "network":
        return None
    now = time.time()
    return next((a for a in sorted(APPROVALS.values(), key=lambda a: a["created"])
                 if (a["service"], a["part"], a["action"]) == (service, part, action) and a["origin"].get("session") == sid
                 and not a.get("used") and (a["status"] == "pending" or now - a.get("decided", now) < TIMEOUT)), None)


def _decision(a):
    """what svc gets: the status, by (one line for messages), approver (username), grant (how long it holds) and the
    reason the user gave for a denial"""
    return {"status": a["status"], "by": a["by"], "approver": a.get("approver", ""), "grant": a.get("grant", ""),
            "reason": a.get("reason", "")}


def use(a):
    """svc learns a decision once – a second call waiting on the same request gets an error and runs nothing
    (network requests are shared on purpose: every connection to that target waits for the one decision)"""
    if a["status"] == "pending" or a["part"] == "network":
        return _decision(a)
    if a.get("used"):
        return {"status": "error", "by": "this approval was already used by another call", "approver": "", "grant": ""}
    a["used"] = True
    save()
    return _decision(a)


def clean_review(diff="", flags=None, risks=None):
    """what svc sends along for the user to review: the diff of a configuration change (≤ 4 KB), possible-injection
    findings and risks only svc knows (an MCP tool the server marks destructive) – shown on the card, never interpreted"""
    out = {}
    if isinstance(diff, str) and diff.strip():
        out["diff"] = diff.replace("\r", "")[:4200]
        lines = out["diff"].splitlines()
        out["added"] = sum(1 for ln in lines if ln.startswith("+"))
        out["removed"] = sum(1 for ln in lines if ln.startswith("-"))
    if isinstance(flags, list):
        f = [re.sub(r"[\x00-\x1f\x7f]+", " ", str(x))[:80] for x in flags[:5] if str(x).strip()]
        if f:
            out["flags"] = f
    if isinstance(risks, list):
        r = [re.sub(r"[\x00-\x1f\x7f]+", " ", str(x))[:80] for x in risks[:5] if str(x).strip()][:3]
        if r:
            out["risks"] = r
    return out


def set_process(rid, found):
    """what `svc origin-of` found for a network request: the process holding the connection and the Claude session or
    job it belongs to (a hint – Claude controls its own processes)"""
    a = APPROVALS.get(rid)
    if not a or not isinstance(found, dict) or not found.get("command"):
        return
    a["process"] = clean_reason(found["command"])
    a["process_user"] = re.sub(r"[^a-z0-9_-]", "", str(found.get("user", "")))[:32]
    o = clean_origin(found.get("origin"))
    if o:
        a["origin"], a["from"] = o, origin_label(o)
    save()


def clean_reason(text):
    """the reason the user gives for a denial: one line, ≤ 200 characters"""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", " ", str(text or ""))).strip()[:200]


def power(service, part):
    """what approving gives, in plain words – Docker on a host is as much as root there; a shell runs as its SSH user"""
    try:
        if part == "docker":
            d = (tclib.load_services(SERVICES_DIR).get(service) or {}).get("docker") or {}
            return f"Docker on {d.get('ssh_host') or service}: control of every container there – the same as root on that host"
        if part == "ssh":
            h = sshhosts.get(service) or {}
            user = "root" if h.get("sudo") else (h.get("user") or "root")
            return f"Shell on {service} as {user}" + (" (sudo)" if h.get("sudo") else "")
    except Exception:  # noqa: BLE001 – a hint only, never in the way of an approval
        pass
    return ""


def create(service, part, action, origin=None, review=None, cid=""):
    """new request; approved at once while a grant for this service + part is active – unless the action is risky
    (tclib.write_risks: a grant never covers those); one pending request per network target; the same request again
    for a session that asks once more after svc handed it back (review: clean_review; cid: the correlation id of the
    svc call, in each of its audit entries)"""
    _expire()
    if part == "network":
        same = next((a for a in APPROVALS.values() if a["status"] == "pending" and a["service"] == service and a["part"] == part), None)
        if same:
            same["attempts"] = same.get("attempts", 1) + 1  # another connection waits for the same decision (saved with the next change)
            return same["id"]
    o = clean_origin(origin)
    same = _again(str(service)[:60], str(part)[:20], str(action)[:500], o)
    if same:
        same["again"] = True
        save()
        return same["id"]
    rid = str(next(_ids))
    a = {"id": rid, "service": str(service)[:60], "part": str(part)[:20], "action": str(action)[:500],
         "created": time.time(), "status": "pending", "by": "", "event": asyncio.Event(), "origin": o, **(review or {})}
    if CID_RE.fullmatch(str(cid or "")):
        a["cid"] = cid
    a["from"] = origin_label(a["origin"])
    if part != "network":
        a["risks"] = (a.get("risks", []) + tclib.write_risks(a["part"], a["action"]))[:4]  # svc's own (clean_review) first
        a["power"] = power(a["service"], a["part"])
    g = active_grant(a["service"], a["part"])
    if g and a.get("risks"):
        a["grant_skipped"] = True  # asked despite the grant: a risky action is approved on its own
    elif g:
        until = time.strftime('%H:%M', time.localtime(g['until']))
        a.update(status="approved", decided=time.time(), by=f"grant until {until} ({g['by']})", approver=g["by"],
                 grant=f"until {until}")
        a["event"].set()
    APPROVALS[rid] = a
    save()
    if a["status"] == "pending":
        notify.emit("approval", f"Approval needed: {a['service']} ({a['part']})" + (" ⚠" if a.get("flags") or a.get("risks") else ""),
                    a["action"] + (f"\nFrom: {a['from']}" if a["from"] else "")
                    + (f"\n⚠ risky: {'; '.join(a['risks'])}" if a.get("risks") else "")
                    + (f"\n⚠ possible prompt injection: {'; '.join(a['flags'])}" if a.get("flags") else ""), key=f"approval:{rid}",
                    link=notify.control_link("/approvals"))
    return rid


def decide(rid, approve, who="tentacontrol", grant=False, seconds=None, reason=""):
    a = APPROVALS.get(rid)
    if not a or a["status"] != "pending":
        return False
    a.update(status="approved" if approve else "denied", decided=time.time(), by=who, approver=who)
    if not approve and clean_reason(reason):
        a["reason"] = clean_reason(reason)
    if approve and grant and a["part"] not in NO_GRANT_PARTS:
        GRANTS[(a["service"], a["part"])] = {"until": time.time() + (seconds or GRANT_SECONDS), "by": who}
        a["grant"] = f"{(seconds or GRANT_SECONDS) // 60} min"
        a["by"] = who + f" + {a['grant']}"
    a["event"].set()
    save()
    return True


def active_grant(service, part):
    g = GRANTS.get((service, part))
    if g and g["until"] > time.time() and part not in NO_GRANT_PARTS:
        return g
    GRANTS.pop((service, part), None)
    return None


def grants():
    now = time.time()
    for k in [k for k, g in GRANTS.items() if g["until"] <= now]:
        GRANTS.pop(k, None)
    return [{"service": s, "part": p, "until_s": time.strftime("%H:%M", time.localtime(g["until"])), **g}
            for (s, p), g in sorted(GRANTS.items(), key=lambda x: x[1]["until"])]


def revoke(service, part):
    gone = GRANTS.pop((service, part), None) is not None
    save()
    return gone


async def wait(rid, seconds):
    a = APPROVALS.get(rid)
    if not a:
        return {"status": "error", "by": "unknown request (tentacontrol restarted?)", "approver": "", "grant": ""}
    if a["status"] == "pending":
        try:
            await asyncio.wait_for(a["event"].wait(), timeout=max(1, min(seconds, 30)))
        except asyncio.TimeoutError:
            pass
    _expire()
    return use(a)


def pending():
    _expire()
    return sorted((a for a in APPROVALS.values() if a["status"] == "pending"), key=lambda a: a["created"])


def origin_link(o):
    """where to look next: the job's run, or the terminal of a session that can be reattached without starting anything"""
    o = clean_origin(o)
    if o.get("job"):
        return f"/jobs#run-{o['job']}"
    return {"claude-workspace": "/terminal?p=claude", "claude-rc": "/terminal?p=rc"}.get(o.get("tmux", ""), "")
