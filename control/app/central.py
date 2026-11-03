"""Central management – this installation as an agent of a central server (tentaclAI Enterprise). Protocol: docs/central.md.

The agent connects to the server, never the other way round: every 30 s a heartbeat, the profile when it changed, the
audit entries not sent yet and – when it changed – the configuration (the export document, plain secrets left out).
A profile (signed by the server) says which items of which parts (backup.SECTIONS) are enforced or defaults; they are
applied through backup.preview/apply, enforced ones are locked (check_write, locks.json for svc) and reverted when
changed around tentacontrol. Without the server the last profile stays in force and audit entries wait.

State in DATA_DIR/central/ (root only): agent.key (Ed25519, PEM), state.json, profile.json (the signed profile as
received), locks.json (enforced item ids – svc reads it), ca.pem (optional: the server's CA), breakglass.json (the
local sign-in opened from the host while the profile allows only sign-ins through the server).
"""
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

from cryptography.exceptions import InvalidSignature

from . import jsonstore
from .config import DATA_DIR
from .log import get

log = get("central")

DIR = os.path.join(DATA_DIR, "central")
KEY_FILE = os.path.join(DIR, "agent.key")
STATE = os.path.join(DIR, "state.json")
PROFILE = os.path.join(DIR, "profile.json")
LOCKS = os.path.join(DIR, "locks.json")
CA_FILE = os.path.join(DIR, "ca.pem")
API = "/api/agent/v1"
CODE_PREFIX = "tce1."
INTERVAL = 30
AUDIT_BATCH = 500
AUDIT_BACKLOG_DAYS = 7
TAMPER_KEEP = 10             # refused attempts kept for the status
TIMEOUT = 15
MODES = ("enforced", "default")

_local = threading.local()  # .applying: writes of the agent itself pass check_write
_lock = threading.RLock()   # one sync at a time


class CentralError(Exception):
    """a problem with the server or the profile – the message is for the admin"""


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fingerprint(pub_b64):
    """the first 16 hex digits of SHA-256 over the raw public key (as tcmanager shows it)"""
    h = hashlib.sha256(b64d(pub_b64)).hexdigest()[:16].upper()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _areas():
    from .backup import SECTIONS
    return dict(SECTIONS, modules="Modules", features="Features (hide parts of tentacontrol)", signin="Sign-in")


def short_label(label):
    """("Site rules", "local/CLAUDE.md") from "Site rules (local/CLAUDE.md)" – the part in brackets is a tooltip"""
    m = re.fullmatch(r"(.+?) \((.+)\)", label)
    return (m.group(1), m.group(2)) if m else (label, "")


def areas():
    """what a server may manage: the parts of the export, modules, and which features of tentacontrol show – short labels
    (the details: area_hints)"""
    return {k: short_label(v)[0] for k, v in _areas().items()}


def area_hints():
    return {k: short_label(v)[1] for k, v in _areas().items() if short_label(v)[1]}


# features a profile can hide here: label, the paths they live under (the page, its actions, its partials)
FEATURES = {
    "terminal": ("Terminal", ("/terminal", "/ws/terminal")),
    "jobs": ("Jobs", ("/jobs", "/partials/job-count")),
    "network": ("Network", ("/network",)),
    "modules": ("Modules", ("/modules",)),
    "claude": ("Claude (instructions, memory, models, skills, usage, settings.json)", ("/claude", "/models", "/skills", "/usage")),
    "backup": ("Export / Import", ("/backup",)),
    "updates": ("Updates", ("/updates",)),
}


def hidden_features():
    """the features the server's profile hides here (only when the agent lets it manage features)"""
    if "features" not in (state().get("areas") or []):
        return set()
    return set((_managed_profile().get("features") or {}).get("hidden") or []) & set(FEATURES)


def hidden_feature_of(path):
    """the hidden feature a path belongs to, or None"""
    hidden = hidden_features()
    for key in hidden:
        if any(path == p or path.startswith(p + "/") for p in FEATURES[key][1]):
            return key
    return None


# ---------------------------------------------------------------- the server's banner

BANNER_LEVELS = ("info", "warn", "critical")


def _clean_banner(b):
    if not isinstance(b, dict) or not str(b.get("text") or "").strip() or not b.get("id"):
        return None
    return {"id": str(b["id"])[:40], "text": str(b["text"]).strip()[:500],
            "level": b.get("level") if b.get("level") in BANNER_LEVELS else "info"}


def banner():
    """the message the server shows on every installation (None: none)"""
    return state().get("banner") if enrolled() else None


# ---------------------------------------------------------------- sign-in through the server (docs/central.md → Sign-in)

BREAKGLASS = os.path.join(DIR, "breakglass.json")
BREAKGLASS_SECONDS = 3600
SSO_ROLES = ("admin",)       # what tentacontrol knows; the server's grants say which
SSO_SKEW = 60                # seconds of clock difference accepted on iat
SSO_PENDING_SECONDS = 600    # a sign-in started here must come back within


def _control_url():
    """CONTROL_URL when it is an http(s) address – the server sends users back there"""
    from .notify import control_link
    url = control_link("")
    return url if url.startswith(("https://", "http://")) else ""


def sso_enabled():
    """users of the server may sign in here: enrolled, "Sign-in" allowed, and an address to come back to"""
    return enrolled() and "signin" in (state().get("areas") or []) and bool(_control_url())


def sign_in_policy():
    """"local" (local accounts and the server) or "enterprise" (only through the server) – the profile says, while
    the agent lets the server manage Sign-in"""
    if not sso_enabled():
        return "local"
    return "enterprise" if (_managed_profile().get("sign_in") or {}).get("policy") == "enterprise" else "local"


def breakglass_until():
    return float((jsonstore.load(BREAKGLASS) or {}).get("until") or 0)


def open_breakglass():
    """open the local sign-in for an hour although the profile allows only the server (./tentaclai.sh passwd)"""
    until = time.time() + BREAKGLASS_SECONDS
    _save({"until": until, "by": "host"}, BREAKGLASS)
    _audit("local sign-in opened for an hour", "emergency access from the host", decision="warn")
    return until


def breakglass_active():
    return breakglass_until() > time.time()


def breakglass_open():
    """the server allows only its own sign-ins, and the host opened the local one for now"""
    return sign_in_policy() == "enterprise" and breakglass_active()


def local_sign_in():
    """may local accounts sign in now? (the server's policy – unless opened from the host)"""
    return sign_in_policy() != "enterprise" or breakglass_active()


def _same(a, b):
    """constant-time comparison of two tokens of any text (compare_digest refuses non-ASCII str)"""
    return secrets.compare_digest(str(a).encode(), str(b).encode())


def sso_start(session):
    """the server's address that starts a sign-in; state and nonce wait in the session"""
    st = state()
    s, n = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    session["sso"] = {"state": s, "nonce": n, "ts": time.time()}
    return st["url"] + "/sso/authorize?" + urlencode({"agent": st["agent_id"], "state": s, "nonce": n,
                                                     "redirect": _control_url() + "/sso/callback"})


def sso_finish(session, token, state_value):
    """the user of a signed assertion from the server – CentralError when it isn't valid for this sign-in"""
    pend = session.pop("sso", None) or {}
    if not sso_enabled():
        raise CentralError("sign-in through the server is not allowed here")
    if not pend or time.time() - pend.get("ts", 0) > SSO_PENDING_SECONDS or not _same(state_value, pend.get("state", "")):
        raise CentralError("this sign-in wasn't started here, or it took too long – try again")
    st = state()
    try:
        body, sig = str(token).split(".", 1)
        raw = b64d(body)
        _check_sig(st, b64d(sig), raw)
        claims = json.loads(raw)
        if not isinstance(claims, dict):
            raise ValueError("not an object")
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise CentralError("the server's answer isn't validly signed") from None
    now = time.time()
    if (claims.get("v") != 1 or claims.get("aud") != st["agent_id"] or not _same(claims.get("nonce"), pend.get("nonce", ""))
            or not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now
            or not isinstance(claims.get("iat", 0), (int, float)) or claims.get("iat", 0) > now + SSO_SKEW
            or claims.get("role") not in SSO_ROLES or not claims.get("sub") or not claims.get("username")):
        raise CentralError("the server's answer is not for this sign-in (expired or meant for another installation)")
    return {"id": "c:" + str(claims["sub"])[:64], "username": str(claims["username"])[:32], "name": str(claims.get("name") or "")[:80],
            "email": str(claims.get("email") or "")[:254], "role": claims["role"], "source": "central",
            "central": st.get("central_name", "")}


# ---------------------------------------------------------------- state

def state():
    return jsonstore.load(STATE) or {}


def _save(data, path=None):
    """state.json, or another file of the central's directory (0700, its files 0600)"""
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    jsonstore.save(path or STATE, data, mode=0o600)


def _update(**kw):
    with _lock:
        st = state()
        st.update(kw)
        _save(st)
        return st


def enrolled():
    st = state()
    return bool(st.get("agent_id")) and not st.get("revoked")


def _key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        pass
    priv = Ed25519PrivateKey.generate()
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with os.fdopen(os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(pem)
    return priv


def _public(priv):
    from cryptography.hazmat.primitives import serialization
    return b64e(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


# ---------------------------------------------------------------- HTTP

def parse_code(code):
    """{url, token, key} from an enrollment code – CentralError if it isn't one"""
    code = "".join(str(code or "").split())
    if not code.startswith(CODE_PREFIX):
        raise CentralError("not an enrollment code (it starts with tce1.)")
    try:
        c = json.loads(b64d(code[len(CODE_PREFIX):]))
    except (ValueError, UnicodeDecodeError):
        raise CentralError("the enrollment code is damaged") from None
    if not isinstance(c, dict) or not all(isinstance(c.get(k), str) and c.get(k) for k in ("url", "token", "key")):
        raise CentralError("the enrollment code is incomplete")
    if not c["url"].startswith(("https://", "http://")):
        raise CentralError("the enrollment code has no server address")
    if c.get("ca") is not None and (not isinstance(c["ca"], str) or "BEGIN CERTIFICATE" not in c["ca"]):
        raise CentralError("the certificate in the enrollment code is not PEM")
    c["url"] = c["url"].rstrip("/")
    return c


def _ssl():
    ctx = ssl.create_default_context()
    if os.path.isfile(CA_FILE):
        ctx.load_verify_locations(CA_FILE)
    return ctx


def _http(method, url, body, headers):
    """(status, body bytes) – the transport; tests replace it"""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl() if url.startswith("https") else None) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _call(method, path, payload=None, signed=True, base=None, raw=False):
    st = state()
    base = base or st.get("url")
    body = canonical(payload) if payload is not None else b""
    headers = {"Content-Type": "application/json", "User-Agent": "tentacontrol-agent/1"}
    if signed:
        ts, nonce = str(int(time.time())), secrets.token_urlsafe(16)
        msg = "\n".join([method, API + path, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
        headers.update({"X-TC-Agent": st["agent_id"], "X-TC-Time": ts, "X-TC-Nonce": nonce,
                        "X-TC-Signature": b64e(_key().sign(msg))})
    try:
        status, data = _http(method, base + API + path, body if method != "GET" else None, headers)
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise CentralError(f"can't reach the server: {reason}") from None
    if status == 410:
        _update(revoked=True, last_error="the server revoked this installation")
        raise CentralError("the server revoked this installation")
    if raw and status == 200:
        return data
    try:
        answer = json.loads(data or b"{}")
    except ValueError:
        answer = {}
    if status != 200:
        raise CentralError(f"server: {answer.get('error') or answer.get('detail') or f'HTTP {status}'}")
    return answer


# ---------------------------------------------------------------- enrolling and leaving

def enroll(code, name, allowed, ca_pem=""):
    """join the server of an enrollment code; allowed = the parts the server may manage. Returns the state."""
    from . import instance
    from .envfile import read_env
    from .web import TC_VERSION
    if enrolled():
        raise CentralError("this installation is enrolled already – leave first")
    c = parse_code(code)
    allowed = sorted(a for a in allowed if a in areas())
    ca_pem = (ca_pem or "").strip() or str(c.get("ca") or "").strip()  # pasted here before the one the server put into the code
    if ca_pem:
        if "BEGIN CERTIFICATE" not in ca_pem:
            raise CentralError("the CA certificate is not PEM")
        os.makedirs(DIR, mode=0o700, exist_ok=True)
        with open(CA_FILE, "w") as f:
            f.write(ca_pem + "\n")
    elif os.path.exists(CA_FILE):
        os.remove(CA_FILE)  # left by an earlier attempt
    env = read_env()
    priv = _key()
    answer = _call("POST", "/enroll", {"token": c["token"], "public_key": _public(priv), "instance_id": instance.instance_id()[0],
                                       "hostname": env.get("TC_HOSTNAME") or socket.gethostname(), "version": TC_VERSION,
                                       "name": (name or env.get("TC_HOSTNAME") or socket.gethostname()).strip()[:60],
                                       "api": 1, "areas": allowed}, signed=False, base=c["url"])
    key = answer.get("central_key") or ""
    if not key or fingerprint(key) != c["key"]:
        raise CentralError("the server's key doesn't match the enrollment code – not enrolled")
    if not isinstance(answer.get("agent_id"), str) or not answer["agent_id"]:
        raise CentralError("the server's answer has no agent id – not enrolled")
    now = time.time()
    st = {"url": c["url"], "agent_id": answer["agent_id"], "central_key": key, "central_name": answer.get("central_name") or c["url"],
          "name": name, "areas": allowed, "enrolled": now, "profile_rev": 0, "applied": {},
          "audit_cursor": {"ts": now - AUDIT_BACKLOG_DAYS * 86400, "id": ""}, "runs_cursor": now, "config_hash": "", "last_ok": now, "last_error": ""}
    _save(st)
    _audit("enrolled", f"{st['central_name']} as {st['agent_id']} – manages: {', '.join(allowed) or 'nothing'}")
    return st


def _managed_profile():
    """the server's profile while it is in force here (enrolled, not revoked) – {} otherwise"""
    return (_profile() or {}) if enrolled() else {}


def tamper_protected():
    """the server's profile protects its management here: no leaving, nothing taken away from what it may manage
    (only revoking on the server ends it). Root on the host can still edit the files – the server notices that"""
    return _managed_profile().get("allow_leave") is False


def areas_locked():
    """the server's profile locks "Managed by Enterprise": the local admin can't change it at all ("all" locks too)"""
    return _managed_profile().get("areas_locked") is True or areas_all()


def areas_all():
    """the server's profile takes over every part ("Managed by Enterprise: all", locked)"""
    return _managed_profile().get("areas_all") is True


def _take_all_areas():
    """under "all" the agent lets the server manage every part – also parts a later version adds"""
    want = sorted(areas())
    if areas_all() and sorted(state().get("areas") or []) != want:
        _store_areas(want, "all parts – set by the server's profile")


def _store_areas(allowed, detail):
    _update(areas=allowed, report_hash="")  # the next sync reports again
    _audit("managed by Enterprise changed", detail)


def _tamper(what):
    """a refused attempt: kept for the status (the server shows it) and in the audit log"""
    with _lock:
        st = state()
        st["tamper"] = ((st.get("tamper") or []) + [{"ts": round(time.time()), "what": what[:200]}])[-TAMPER_KEEP:]
        _save(st)
    _audit(f"tamper protection: {what}", "refused – the server's profile protects its management here", decision="blocked")


def set_areas(allowed):
    """the local admin changes what the server may manage – applied at the next sync (parts taken away keep their
    values and are no longer locked). Under tamper protection parts can only be added"""
    st = state()
    if not st.get("agent_id"):
        raise CentralError("not enrolled")
    allowed = sorted({a for a in allowed if a in areas()})
    current = sorted(st.get("areas") or [])
    if allowed == current:
        return allowed
    if areas_locked():
        _tamper("change what the server may manage")
        raise CentralError("the server's profile locks what it manages here – ask the server's admin")
    gone = sorted(set(current) - set(allowed))
    if gone and tamper_protected():
        _tamper(f"take away {', '.join(gone)}")
        raise CentralError("tamper protection: the server's profile doesn't allow taking parts away here – "
                           "ask the server's admin")
    _store_areas(allowed, ", ".join(allowed) or "nothing")
    return allowed


def leave():
    """leave the server (told when it can be reached) – locks go, applied values stay"""
    st = state()
    if not st.get("agent_id"):
        raise CentralError("not enrolled")
    if tamper_protected():
        _tamper("leave the server")
        raise CentralError("tamper protection: the server's profile doesn't allow leaving here – ask the server's admin "
                           "to revoke this installation")
    if not st.get("revoked"):
        with contextlib.suppress(CentralError, KeyError):
            _call("POST", "/leave", {})
    for f in (STATE, PROFILE, LOCKS):
        with contextlib.suppress(FileNotFoundError):
            os.remove(f)
    _audit("left", st.get("central_name", ""))


# ---------------------------------------------------------------- locks

def locks():
    return set((jsonstore.load(LOCKS) or {}).get("enforced") or [])


def locked(section, key):
    return f"{section}:{key}" in locks()


@contextlib.contextmanager
def applying():
    _local.applying = True
    try:
        yield
    finally:
        _local.applying = False


def is_applying():
    """True while the agent applies a profile (the stores then write what the server sent)"""
    return getattr(_local, "applying", False)


def check_write(section, key):
    """ValueError when the server enforces this item – called by the stores before they write"""
    if getattr(_local, "applying", False) or not os.path.exists(LOCKS):
        return
    if locked(section, key):
        raise ValueError(f"{section} {key} is managed by {state().get('central_name') or 'the central server'} – change it there")


# ---------------------------------------------------------------- the profile

def _profile():
    p = jsonstore.load(PROFILE)
    return (p or {}).get("profile")


def _check_sig(st, sig, raw):
    """InvalidSignature (or KeyError/ValueError) unless the server's key signed raw"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(b64d(st["central_key"])).verify(sig, raw)


def _verify(doc, st):
    try:
        prof, sig = doc["profile"], b64d(doc["sig"])
        _check_sig(st, sig, canonical(prof))
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise CentralError("the profile's signature doesn't match the server's key – not applied") from None
    if prof.get("agent_id") != st["agent_id"]:
        raise CentralError("the profile is for another agent – not applied")
    return prof


def _h(v):
    return hashlib.sha256(canonical(v)).hexdigest()[:16]


def reconcile(prof=None):
    """apply a profile (default: the stored one) – returns the report {rev, results, drift, missing, refused, touched,
    restart}; touched: parts written (services … need a sync), restart: settings that need a restart"""
    from . import backup
    from .envfile import read_env
    st = state()
    prof = prof if prof is not None else _profile()
    if not prof:
        return {"rev": 0, "results": [], "drift": [], "missing": [], "refused": [], "touched": [], "restart": []}
    allowed = set(st.get("areas") or [])
    sections = {s: v for s, v in (prof.get("sections") or {}).items() if s in backup.SECTIONS}
    refused = sorted(s for s in sections if s not in allowed) + (["modules"] if prof.get("modules") and "modules" not in allowed else [])
    refused += ["features"] if (prof.get("features") or {}).get("hidden") and "features" not in allowed else []
    sections = {s: v for s, v in sections.items() if s in allowed}
    modes = {k: v for k, v in (prof.get("modes") or {}).items() if v in MODES}
    doc = dict({"format": backup.FORMAT, "version": backup.VERSION, "variables": []}, **sections)
    rows = backup.preview(doc) if sections else {}
    applied = dict(st.get("applied") or {})
    results, drift, pick = [], [], set()
    managed_ids = set()
    for sec, rs in rows.items():
        for r in rs:
            rid, mode = r["id"], modes.get(r["id"], "enforced")
            managed_ids.add(rid)
            if r["status"] == "invalid":
                results.append({"id": rid, "result": "invalid", "msg": r["error"]})
            elif r["status"] == "same":
                applied[rid] = r["hash_new"]
            elif mode == "enforced":
                pick.add(rid)
                if rid in applied:
                    drift.append({"id": rid, "kind": "reverted"})
            elif r["status"] == "new" and rid not in applied:
                pick.add(rid)
            elif r["status"] == "changed" and applied.get(rid) == r["hash_old"]:
                pick.add(rid)  # still the previous profile value: the new default replaces it
            else:
                drift.append({"id": rid, "kind": "overridden" if r["status"] == "changed" else "removed locally"})
    restart, touched = [], set()
    if pick:
        old_env = read_env()
        with applying():
            res, _ = backup.apply(doc, pick)
        hashes = {r["id"]: r["hash_new"] for rs in rows.values() for r in rs}
        for r in res:
            if r["ok"]:
                applied[r["id"]] = hashes.get(r["id"], "")
                touched.add(r["id"].split(":", 1)[0])
            results.append({"id": r["id"], "result": "applied" if r["ok"] else "failed", "msg": r["msg"]})
        from .config import RESTART_VARS
        changed = {r["id"].split(":", 1)[1] for r in res if r["ok"] and r["id"].startswith("settings:")}
        restart = sorted(RESTART_VARS & changed)
        if restart:
            from .web import mark_restart
            mark_restart(old_env, set(restart))
    drift += _local_items(prof, sections, managed_ids)
    results += _gone_jobs(applied, managed_ids, allowed)
    results += _modules(prof, allowed, applied, drift)
    applied = {k: v for k, v in applied.items() if k in managed_ids or k.startswith("modules:")}
    enforced = sorted(rid for rid in managed_ids if modes.get(rid, "enforced") == "enforced")
    enforced += sorted(f"modules:{n}" for n, m in (prof.get("modules") or {}).items()
                       if "modules" in allowed and (m or {}).get("mode", "enforced") == "enforced")
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    jsonstore.save(LOCKS, {"central": st.get("central_name", ""), "enforced": enforced}, mode=0o644)
    missing = backup.missing(doc) if sections else []
    _update(applied=applied, applied_rev=prof.get("rev", 0), drift=drift, missing=missing, refused=refused)
    for r in results:
        if r["result"] in ("applied", "failed"):
            _audit(f"profile {r['result']}: {r['id']}", r["msg"], decision="ok" if r["result"] == "applied" else "failed")
    for d in drift:
        if d["kind"] == "reverted":
            _audit(f"local change reverted: {d['id']}", "enforced by the central profile", decision="denied")
    return {"rev": prof.get("rev", 0), "results": results, "drift": drift, "missing": missing, "refused": refused,
            "touched": sorted(touched), "restart": restart}


def _gone_jobs(applied, managed_ids, allowed):
    """jobs the server handed out and took back (deleted there or out of the profile) are deleted here too – they were
    the server's; other parts stay as local items"""
    from . import scheduled
    out = []
    if "jobs" not in allowed:
        return out
    for rid in [r for r in applied if r.startswith("jobs:") and r not in managed_ids]:
        jid = rid.split(":", 1)[1]
        applied.pop(rid, None)
        if scheduled.get(jid) is None:
            continue
        try:
            with applying():
                scheduled.delete(jid)
            out.append({"id": rid, "result": "applied", "msg": "deleted – no longer in the profile"})
        except ValueError as e:
            out.append({"id": rid, "result": "failed", "msg": str(e)})
    return out


def _local_items(prof, sections, managed_ids):
    """local items in parts where the profile allows none – reported, never deleted"""
    from . import backup
    out = []
    flags = prof.get("local_items") or {}
    current, _ = backup.export([s for s in sections if flags.get(s) is False])
    for s in (s for s in sections if flags.get(s) is False):
        data = current.get(s)
        keys = []
        if isinstance(data, dict) and s == "network":
            keys = [f"{kind}:{e}" for kind, entries in data.items() if isinstance(entries, list) for e in entries]
        elif isinstance(data, dict):
            keys = list(data)
        elif isinstance(data, list):
            keys = [h.get("alias") for h in data if isinstance(h, dict)]
        out += [{"id": f"{s}:{k}", "kind": "local item"} for k in keys if f"{s}:{k}" not in managed_ids]
    return out


def _modules(prof, allowed, applied, drift):
    """built-in modules on/off and packages from the server (installed only when signed by tentaclAI)"""
    from . import extensions, packages
    mods = prof.get("modules") or {}
    if not mods or "modules" not in allowed:
        return []
    out, found = [], {}  # found: installed packages and available modules, looked up once – again after an install

    def lookup():
        if not found:
            found.update(versions=packages.installed_versions(), origins={e["name"]: e["origin"] for e in extensions.available()})
        return found
    for name, m in mods.items():
        m = m or {}
        rid = f"modules:{name}"
        try:
            pkg = m.get("package")
            if pkg:
                have = lookup()["versions"].get(name)
                if have != pkg.get("version"):
                    data = _call("GET", f"/packages/{name}/{pkg['version']}", raw=True)
                    if pkg.get("sha256") and hashlib.sha256(data).hexdigest() != pkg["sha256"]:
                        raise CentralError("the package from the server doesn't match the profile's checksum")
                    got = packages.inspect(data)  # another package or version would be installed again every sync
                    if (got["name"], got["version"]) != (name, pkg.get("version")):
                        raise CentralError(f"the server sent {got['name']} {got['version']}, the profile names {name} {pkg.get('version')}")
                    with applying():
                        info = packages.install(data)  # signed by tentaclAI only (allow_unsigned is False)
                    found.clear()
                    out.append({"id": rid, "result": "applied", "msg": f"package {info['version']} installed – restart tentacontrol"})
            want = m.get("enabled")
            kind = lookup()["origins"].get(name, "")
            if want and kind == "local" and name not in extensions.enabled():  # third-party code (local/extensions, unsigned package): on only by the admin here
                raise ValueError(f"{name} is a local module – the server can switch it off, not on")
            if want is not None and extensions.origin(name) not in ("configured", "signed"):
                on = name in extensions.enabled()
                if on != bool(want) and (m.get("mode", "enforced") == "enforced" or rid not in applied):
                    with applying():
                        extensions.set_enabled(name, bool(want))
                    out.append({"id": rid, "result": "applied", "msg": "enabled" if want else "disabled"})
                elif on != bool(want):
                    drift.append({"id": rid, "kind": "overridden"})
            applied[rid] = _h(m)
        except (CentralError, packages.PackageError, ValueError, KeyError) as e:
            out.append({"id": rid, "result": "failed", "msg": str(e)})
    return out


# ---------------------------------------------------------------- audit shipping

def _unsent(limit=AUDIT_BATCH):
    """(entries oldest first, more waiting) after the cursor"""
    import tclib
    cur = state().get("audit_cursor") or {}
    since, after = float(cur.get("ts") or 0), cur.get("id") or ""
    newer = []
    for line in tclib.audit_lines(DATA_DIR, since - 1):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        if e.get("decision") == "started":
            continue  # the "started" entry of a write (svc, fail closed) – the central gets its result
        if after and e.get("id") == after:
            break
        t = tclib.audit_epoch(e.get("ts"))
        if t and t < since:
            break
        newer.append(e)
    newer.reverse()
    return newer[:limit], len(newer) > limit


def _for_central(batch):
    """copies with what the central can't look up itself: owner – the account of this installation (Community has
    one; Claude, jobs and the system act for it) – and source, the readable origin ("Claude terminal · “title”")"""
    from . import auth
    from .activity import origin_label
    import tclib
    owner = (auth.admin() or {}).get("username", "")
    out = []
    for e in batch:
        e = dict(e, owner=owner)
        o = tclib.audit_origin(e)
        if o:
            try:
                e["source"] = origin_label(o)
            except Exception:  # noqa: BLE001 – a label is a nicety, shipping must go on
                pass
        out.append(e)
    return out


def ship_audit():
    """send what is waiting, in batches – returns the number sent"""
    import tclib
    sent = 0
    for _ in range(20):  # at most 10 000 per sync
        batch, more = _unsent()
        if not batch:
            break
        _call("POST", "/audit", {"entries": _for_central(batch)})
        last = batch[-1]
        _update(audit_cursor={"ts": tclib.audit_epoch(last.get("ts")) or time.time(), "id": last.get("id", "")})
        sent += len(batch)
        if not more:
            break
    return sent


def retention_floor():
    """days the local audit retention must at least keep, so nothing unsent is pruned (0 = no constraint)"""
    if not enrolled():
        return 0
    ts = float((state().get("audit_cursor") or {}).get("ts") or 0)
    return int((time.time() - ts) // 86400) + 2 if ts else 0


# ---------------------------------------------------------------- one sync

def _status(st):
    from . import extensions, instance, services_store
    from .envfile import read_env
    from .web import TC_VERSION
    env = read_env()
    _, waiting = _unsent(1)
    return {"name": st.get("name") or env.get("TC_HOSTNAME", ""), "hostname": env.get("TC_HOSTNAME") or socket.gethostname(),
            "instance_id": instance.instance_id()[0], "version": TC_VERSION, "edition": extensions.edition(),
            "modules": [{"name": e["name"], "title": e.get("title") or e["name"], "origin": e["origin"], "version": e.get("version", ""),
                         "active": e["active"]}
                        for e in extensions.available()],
            "services": [{"name": s["name"], "parts": s["kinds"], "state": s["state"], "enabled": s["enabled"]}
                         for s in services_store.load_all()],
            "audit": {"sent_through": (st.get("audit_cursor") or {}).get("id", ""), "waiting": bool(waiting)},
            "profile": {"rev": st.get("applied_rev", 0), "drift": st.get("drift") or [], "missing": st.get("missing") or [],
                        "refused": st.get("refused") or []},
            "areas": st.get("areas") or [],
            "jobs": _job_states(),
            "control_url": _control_url(),
            "tamper": st.get("tamper") or []}


# ---------------------------------------------------------------- jobs from the server

RUNS_BATCH = 50


def managed_jobs():
    """ids of the jobs the stored profile hands out (none when the agent doesn't let the server manage jobs)"""
    if "jobs" not in (state().get("areas") or []):
        return set()
    return set(((_profile() or {}).get("sections") or {}).get("jobs") or {})


def _job_states():
    """the server's jobs here: on or paused, next run, the last run's outcome"""
    from . import scheduled
    jobs, ids = scheduled.load(), managed_jobs()
    last = {}
    for r in scheduled.history():
        if r.get("job") in ids:
            last[r["job"]] = r
    return [{"id": jid, "name": jobs[jid].get("name", jid), "enabled": bool(jobs[jid].get("enabled")),
             "next": jobs[jid].get("next") if jobs[jid].get("enabled") else None,
             "last_status": (last.get(jid) or {}).get("status", "")} for jid in sorted(ids) if jid in jobs]


def _run_record(r):
    """what the server gets of a finished run"""
    res = r.get("result") if isinstance(r.get("result"), dict) else {}
    return {"id": r["id"], "job": r.get("job", ""), "name": r.get("name", ""), "trigger": r.get("trigger", ""),
            "status": r.get("status", ""), "queued": r.get("queued"), "started": r.get("started"), "ended": r.get("ended"),
            "seconds": r.get("seconds"), "error": str(r.get("error") or "")[:2000],
            "result": {k: str(res.get(k) or "")[:20000 if k == "details" else 2000] for k in ("status", "title", "summary", "details") if res.get(k)},
            "proposals": len(r.get("actions") or [])}


def ship_runs():
    """finished runs of the server's jobs after the cursor – returns the number sent"""
    from . import scheduled
    ids = managed_jobs()
    since = float(state().get("runs_cursor") or 0)
    done = sorted((r for r in scheduled.history() if r.get("job") in ids and r.get("ended") and r["ended"] > since
                   and r.get("status") not in ("queued", "running")), key=lambda r: r["ended"])
    sent = 0
    while done[sent:]:
        batch = done[sent:sent + RUNS_BATCH]
        _call("POST", "/runs", {"runs": [_run_record(r) for r in batch]})
        _update(runs_cursor=batch[-1]["ended"])
        sent += len(batch)
    return sent


def _run_requested(jids):
    """"run now" from the server – only its own jobs"""
    from . import scheduled
    ids = managed_jobs()
    for jid in jids if isinstance(jids, list) else []:
        if jid not in ids:
            continue
        try:
            scheduled.run_now(jid, trigger="central")
            _audit(f"job started: {jid}", "run now from the central")
        except ValueError as e:
            _audit(f"job not started: {jid}", str(e), decision="failed")


def sync():
    """heartbeat, profile, audit, config – one round; returns the report of the profile run (or None).
    CentralError when the server can't be reached (the state keeps the error)."""
    from . import backup
    with _lock:
        st = state()
        if not st.get("agent_id") or st.get("revoked"):
            return None
        try:
            hb = _call("POST", "/heartbeat", _status(st))
            report = None
            if hb.get("profile_rev") != st.get("profile_rev"):
                doc = _call("GET", "/profile")
                prof = _verify(doc, st)
                jsonstore.save(PROFILE, doc, mode=0o600)
                _update(profile_rev=prof.get("rev", 0), profile_at=time.time())
                _audit("profile received", f"{prof.get('name', '')} rev {prof.get('rev')}")
            _take_all_areas()
            report = reconcile()
            key = _h({k: report[k] for k in ("rev", "results", "drift", "missing", "refused")})
            if key != state().get("report_hash"):
                _call("POST", "/report", {k: report[k] for k in ("rev", "results", "drift", "missing", "refused")})
                _update(report_hash=key)
            b = _clean_banner(hb.get("banner"))
            if b != st.get("banner"):
                _update(banner=b)
            _run_requested(hb.get("run_jobs"))
            ship_audit()
            ship_runs()
            cfg, _ = backup.export([s for s in backup.SECTIONS])
            cfg.pop("created", None)
            catalog = settings_catalog()
            ch = _h({"config": cfg, "catalog": catalog})
            if ch != state().get("config_hash") or hb.get("want_config"):
                _call("POST", "/config", {"config": cfg, "hash": ch, "settings_catalog": catalog})
                _update(config_hash=ch)
            _update(last_ok=time.time(), last_error="")
            return report
        except CentralError as e:
            _update(last_error=str(e), last_try=time.time())
            raise


async def loop():
    """the background sync – started with tentacontrol; quiet while not enrolled"""
    import asyncio
    from .web import sync_services
    await asyncio.sleep(10)
    while True:
        if enrolled():
            try:
                report = await asyncio.to_thread(sync)
                if report and set(report["touched"]) & {"ssh_hosts", "systems", "services", "instructions", "skills"}:
                    await sync_services()
            except CentralError:
                pass
            except Exception as e:  # noqa: BLE001 – never end the loop
                log.warning(f"central: sync failed: {e}")
                _update(last_error=f"internal error: {e}")
        await asyncio.sleep(INTERVAL)


def settings_catalog():
    """the settings of Settings as the central's profile editor offers them: [{key, label, help, type, group}] – the
    ones a profile can set (no read-only ones, no credentials)"""
    from .config import SETTINGS_GROUPS, is_secret
    return [{"key": k, "label": label, "help": hlp, "type": kind, "group": group}
            for group, rows in SETTINGS_GROUPS for k, label, hlp, kind in rows if kind != "readonly" and not is_secret(k)]


def _audit(action, detail="", decision="ok"):
    from . import auditlog
    auditlog.write("admin", "central", f"central: {action}", decision, actor="system", detail=detail[:300])


def nav_status():
    """the sidebar's Enterprise entry: none (not enrolled), ok (in touch), err (the last sync failed or no contact for
    a while), revoked – with a one-line title"""
    st = state()
    if not st.get("agent_id"):
        return {"state": "none", "title": "tentaclAI Enterprise – central management of many installations"}
    name = st.get("central_name") or "tentaclAI Enterprise"
    if st.get("revoked"):
        return {"state": "revoked", "name": name, "title": f"{name}: this installation was revoked"}
    if st.get("last_error") or time.time() - float(st.get("last_ok") or 0) > 4 * INTERVAL:
        return {"state": "err", "name": name, "title": f"{name}: connection failed – {st.get('last_error') or 'no contact'}"[:200]}
    return {"state": "ok", "name": name, "title": f"Managed by {name}"}


def view():
    """for the Enterprise page"""
    st = state()
    prof = _profile() or {}
    bg = breakglass_until() if breakglass_active() else 0

    def fmt(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""
    _, waiting = _unsent(1) if st.get("agent_id") else ([], False)
    return {"enrolled": bool(st.get("agent_id")), "revoked": bool(st.get("revoked")), "st": st, "profile": prof,
            "locks": sorted(locks()), "areas": areas(), "area_hints": area_hints(), "ca": os.path.isfile(CA_FILE), "nav": nav_status(),
            "last_ok": fmt(st.get("last_ok")), "enrolled_at": fmt(st.get("enrolled")), "profile_at": fmt(st.get("profile_at")),
            "audit_waiting": bool(waiting), "jobs": sorted(managed_jobs()) if st.get("agent_id") else [],
            "hidden": [short_label(FEATURES[k][0]) for k in sorted(hidden_features())], "banner": banner(),
            "protected": tamper_protected(), "areas_locked": areas_locked(), "areas_all": areas_all(),
            "sign_in_policy": sign_in_policy(), "control_url": _control_url(), "breakglass_until": fmt(bg)}
