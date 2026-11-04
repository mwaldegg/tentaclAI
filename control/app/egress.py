"""Network rules of the egress gateway: own allow/block lists (data/control/egress-rules.json), the shipped default
list and the tentacles (derived live from services and SSH hosts – never stored, so they can't go stale).

EGRESS_MODE=learn (new installations): permissive for EGRESS_LEARN_MINUTES (60) from the first reported connection,
then enforce – the destinations seen meanwhile without a rule are offered for the allowlist (data/control/egress-learn.json)."""
import os
import re
import time

import tclib

from . import activity, jsonstore, sshhosts
from .central import check_write
from .config import DATA_DIR, SERVICES_DIR, STACK_DIR
from .envfile import read_env

RULES = os.path.join(DATA_DIR, "egress-rules.json")
LEARN = os.path.join(DATA_DIR, "egress-learn.json")  # {started, ended, dismissed} of the learning phase
CLEARED = os.path.join(DATA_DIR, "egress-cleared")  # time of the last "Clear" – the gateway empties its list after it
SEEN = "/egress/egress-seen.json"
DEFAULT_FILE = "/app/egress-default.txt"
ENTRY_RE = re.compile(r"^((\*\.)?[a-z0-9.-]{1,253}|\d{1,3}(\.\d{1,3}){3}/\d{1,2})(:\d{1,5})?\Z")


def default_list():
    try:
        return tclib.egress_patterns(open(DEFAULT_FILE).read())
    except OSError:
        return []


def rules():
    r = jsonstore.load(RULES)
    return {"allow": r.get("allow", []), "block": r.get("block", [])}


def _save(r):
    jsonstore.save(RULES, r)


def normalize(entry):
    e = (entry or "").strip().lower().rstrip(".")
    if not ENTRY_RE.match(e):
        raise ValueError("host, *.domain, IP or CIDR (10.0.0.0/8), optionally with :port")
    return e


def add(kind, entry):
    check_write("network", f"{kind}:{normalize(entry)}")
    e = normalize(entry)
    if kind == "block":
        host, _, port = e.rpartition(":") if ":" in e else (e, "", "443")
        if any(tclib.egress_match(p, host.lstrip("*."), int(port or 443)) for p in default_list()):
            raise ValueError(f"{e} is on the built-in list (Claude Code itself) and can't be blocked")
    with jsonstore.locked(RULES):
        r = rules()
        other = "block" if kind == "allow" else "allow"
        host = e.rsplit(":", 1)[0] if ":" in e else e
        r[other] = [x for x in r[other] if x not in (e, host)]  # an entry lives in one list only (host:port or the plain host)
        if e not in r[kind]:
            r[kind].append(e)
        _save(r)
    return e


def remove(kind, entry):
    check_write("network", f"{kind}:{entry}")
    with jsonstore.locked(RULES):
        r = rules()
        r[kind] = [x for x in r[kind] if x != entry]
        _save(r)


def still_blocked(entry):
    """a wildcard on the blocklist that keeps blocking this host:port after it was allowed, else ''"""
    host, _, port = entry.rpartition(":") if ":" in entry else (entry, "", "443")
    return next((p for p in rules()["block"] if tclib.egress_match(p, host, int(port or 443))), "")


def direct_ip():
    """what enforce does with connections to a bare IP address that no rule covers: block (default) or ask"""
    v = (read_env().get("EGRESS_DIRECT_IP") or "block").strip().lower()
    return v if v in ("ask", "block") else "block"


def cleared():
    try:
        return float(open(CLEARED).read().strip())
    except (OSError, ValueError):
        return 0.0


def clear_seen():
    import time
    with open(CLEARED, "w") as f:
        f.write(str(time.time()))


def configured():
    """EGRESS_MODE as set: permissive, enforce or learn"""
    m = (read_env().get("EGRESS_MODE") or "permissive").strip().lower()
    return m if m in ("permissive", "enforce", "learn") else "permissive"


def learn_seconds():
    try:
        return max(1, int(read_env().get("EGRESS_LEARN_MINUTES") or 60)) * 60
    except ValueError:
        return 3600


def learning():
    """the learning phase: {started, until, ended, dismissed} – started 0 while no connection came yet; {} when the
    mode was never learn"""
    st = jsonstore.load(LEARN)
    if configured() != "learn" and not st:
        return {}
    started = float(st.get("started") or 0)
    return dict(st, started=started, until=started + learn_seconds() if started else 0)


def learn_start():
    """the first connection the gateway reports in learn mode starts the clock"""
    if configured() == "learn" and not jsonstore.load(LEARN).get("started"):
        jsonstore.save(LEARN, {"started": time.time()})


def mode():
    """the mode the gateway applies: learn is permissive until the phase is over – then .env says enforce"""
    m = configured()
    if m != "learn":
        return m
    st = learning()
    if not st["started"] or time.time() < st["until"]:
        return "permissive"
    try:
        from .envfile import update_env
        update_env({"EGRESS_MODE": "enforce"})
    except Exception:  # noqa: BLE001 – a setting the central enforces: it decides the mode
        return "permissive"
    jsonstore.save(LEARN, {"started": st["started"], "ended": time.time()})
    from . import notify
    n = len(learned())
    notify.emit("learned", "Network: learning phase over – enforce is on",
                f"{n} destination{'s' if n != 1 else ''} without a rule to review on the Network page" if n else
                "Every destination had a rule.", key="learned", link=notify.control_link("/network"))
    return "enforce"


def learned():
    """destinations first seen during the learning phase that still have no rule – offered for the allowlist"""
    st = learning()
    if not st.get("started") or st.get("dismissed"):
        return []
    end = st.get("ended") or st["until"]
    return [r for r in seen_rows() if r["kind"] == "unknown" and st["started"] - 60 <= r.get("first", 0) <= end]


def learned_allow():
    """every learned destination onto the allowlist → (how many, the ones that couldn't go there – an address the
    list can't hold, e.g. IPv6, or an entry the central server manages: with the reason)"""
    rows, skipped = learned(), []
    for r in rows:
        try:
            add("allow", f"{r['host']}:{r['port']}")
        except ValueError as e:
            skipped.append(f"{r['host']}:{r['port']} ({e})")
    learned_dismiss()
    return len(rows) - len(skipped), skipped


def learned_dismiss():
    jsonstore.save(LEARN, dict(jsonstore.load(LEARN), dismissed=time.time()))


def tentacles():
    """{(host, port|None): name} of all active services and SSH hosts"""
    return tclib.reach_hosts(tclib.load_services(SERVICES_DIR, tclib.load_systems(STACK_DIR)), read_env(), sshhosts.hosts())


def policy():
    """what the gateway needs – no secrets"""
    r = rules()
    grants = {g["service"]: g["until"] for g in activity.grants() if g["part"] == "network"}
    return {"mode": mode(), "direct_ip": direct_ip(), "cleared": cleared(), "allow": r["allow"], "block": r["block"], "grants": grants,
            "tentacles": [[h, p, n] for (h, p), n in tentacles().items()]}


def origin(host, port, tent=None, r=None):
    """(kind, label): default (built-in, never blocked) / blocked / tentacle / allow / unknown"""
    tent = tentacles() if tent is None else tent
    r = rules() if r is None else r
    return tclib.egress_rule(host, port, (), default_list(), r["block"], r["allow"], tent)


def seen_rows():
    seen = jsonstore.load(SEEN)
    tent, r, since = tentacles(), rules(), cleared()
    rows = []
    for key, e in seen.items():
        if e.get("last", 0) <= since:
            continue
        host, _, port = key.rpartition(":")
        kind, label = origin(host, int(port) if port.isdigit() else 0, tent, r)
        rows.append(dict(e, host=host, port=port, kind=kind, label=label))
    return sorted(rows, key=lambda x: -x.get("last", 0))
