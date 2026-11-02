"""Usage of the sandbox's Claude: plan limits from `claude -p "/usage"` and token totals from the local session files.

Plan limits (session / week, account-wide) come from Claude Code itself – the same numbers as in the claude.ai profile.
Token totals are read from ~/.claude/projects/*/*.jsonl of user claude: only usage fields, model, time, session id,
entrypoint and the session title – never the conversation. Both are cached in DATA_DIR.
"""
import glob
import json
import os
import re
import time

from . import dockerops, jsonstore
from .config import DATA_DIR, STACK_DIR

PLAN_CACHE = os.path.join(DATA_DIR, "usage-plan.json")
LOCAL_CACHE = os.path.join(DATA_DIR, "usage-local.json")
WARNED = os.path.join(DATA_DIR, "usage-warned.json")
PROJECTS = os.path.join(STACK_DIR, "data", "claude", ".claude", "projects")
KEEP_DAYS = 60

LIMIT_RE = re.compile(r"^Current (session|week)(?: \(([^)]*)\))?:\s*(\d+)% used(?:\s*·\s*resets (.+))?$", re.M)
SUMMARY_RE = re.compile(r"Last (\w+) · (\d+) requests · (\d+) sessions")


TIP_RE = re.compile(r"^(\d+)%\s+(.+)$")
TOP_RE = re.compile(r"^Top ([^:]+):\s*(.+)$")


def parse_plan(text):
    """plan limits, and "what contributes" as one block per period (Claude Code prints e.g. last 24h and last 7d):
    {label, requests, sessions, tips: [{pct, text}], tops: [{what, items}]}"""
    limits = [{"window": m.group(1), "scope": m.group(2) or "", "percent": int(m.group(3)), "resets": re.sub(r"\s*\([^)]*\)\s*$", "", (m.group(4) or "").strip())}
              for m in LIMIT_RE.finditer(text)]
    lines = text.splitlines()
    periods, cur = [], None
    for line in lines:
        s = SUMMARY_RE.search(line)
        if s:
            cur = {"label": s.group(1), "requests": int(s.group(2)), "sessions": int(s.group(3)), "tips": [], "tops": []}
            periods.append(cur)
            continue
        item = line.strip()
        if cur is None or not item:
            continue
        t, tip = TOP_RE.match(item), TIP_RE.match(item)
        if t:
            cur["tops"].append({"what": t.group(1), "items": t.group(2)})
        elif tip:
            cur["tips"].append({"pct": int(tip.group(1)), "text": re.sub(r"^of your usage\s+", "", tip.group(2)).replace(" · run ", " – run ")})
        else:
            cur["tips"].append({"pct": None, "text": item})
    billing = next((l.strip() for l in lines if l.strip() and not l.startswith("Warning:")), "")
    billing = "" if LIMIT_RE.match(billing) else billing
    note = next((l.strip() for l in lines if l.strip().startswith("Approximate")), "")
    return {"limits": limits, "billing": billing, "periods": periods, "note": note}


def refresh_plan():
    """ask Claude Code (`/usage` works without a model call); keeps the last good answer when it fails"""
    code, out = dockerops.run(["timeout", "60", "claude", "-p", "--no-session-persistence", "/usage"], workdir="/workspace", user=dockerops.CLAUDE_USER)
    data = {"checked": time.time(), "raw": out.strip()[:4000], "ok": code == 0, **parse_plan(out)}
    if code != 0 or not data["limits"]:
        old = plan()
        if old.get("limits"):
            old.update(checked_failed=time.time(), raw_failed=out.strip()[:1000])
            data = old
    jsonstore.save(PLAN_CACHE, data, indent=None)
    return data


def plan():
    return jsonstore.load(PLAN_CACHE)


QUOTA_LEVELS = (80, 100)


def quota_alerts(limits, warned):
    """the limits that just crossed a level (80 %, 100 %) – once per window: the level is kept until the usage drops
    below 80 % again (a new window). Not keyed by the reset time: Claude Code prints it to the minute and it shifts."""
    alerts = []
    for lim in limits:
        k = f"{lim['window']}:{lim['scope']}"
        level = max((lv for lv in QUOTA_LEVELS if lim["percent"] >= lv), default=0)
        if level > warned.get(k, 0):
            alerts.append(lim)
        warned[k] = max(level, warned.get(k, 0)) if level else 0
    return alerts


def check_quota(limits):
    """quota_alerts with the state kept in DATA_DIR – a restart of tentacontrol does not warn again"""
    warned = jsonstore.load(WARNED)
    alerts = quota_alerts(limits, warned)
    jsonstore.save(WARNED, warned, indent=None)
    return alerts


def _local():
    d = jsonstore.load(LOCAL_CACHE)
    d.setdefault("offsets", {})
    d.setdefault("days", {})       # "YYYY-MM-DD" → model → counters
    d.setdefault("sessions", {})   # session id → info
    return d


def session_files():
    """Claude's session files – regular files inside PROJECTS only: the directory belongs to Claude, and tentacontrol
    (root) must not follow a symlink it put there"""
    claude_home = os.path.dirname(os.path.dirname(PROJECTS))  # data/claude – tentaclAI's own; below it Claude's
    d = PROJECTS
    while d != claude_home:  # projects/ or .claude/ a symlink: realpath below would already point elsewhere
        if os.path.islink(d):
            return []
        d = os.path.dirname(d)
    root = os.path.realpath(PROJECTS) + os.sep
    out = []
    for path in glob.glob(os.path.join(PROJECTS, "*", "*.jsonl")):
        if os.path.islink(path) or os.path.islink(os.path.dirname(path)) or not os.path.realpath(path).startswith(root):
            continue
        out.append(path)
    return out


def refresh_local():
    """read only what was appended since the last run"""
    d = _local()
    for path in session_files():
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        start = d["offsets"].get(path, 0)
        if start > size:
            start = 0  # rewritten
        if start == size:
            continue
        project = os.path.basename(os.path.dirname(path))
        with open(path, "rb") as f:
            f.seek(start)
            chunk = f.read()
        end = chunk.rfind(b"\n") + 1  # only complete lines
        for raw in chunk[:end].splitlines():
            try:
                e = json.loads(raw)
            except ValueError:
                continue
            sid = e.get("sessionId") or os.path.basename(path)[:-6]
            s = d["sessions"].setdefault(sid, {"project": project, "entry": "", "title": "", "first": "", "last": "",
                                               "tokens": 0, "replies": 0, "model": ""})
            if e.get("entrypoint"):
                s["entry"] = e["entrypoint"]
            if e.get("aiTitle"):
                s["title"] = str(e["aiTitle"])[:80]
            m = e.get("message") if isinstance(e.get("message"), dict) else {}
            u = m.get("usage") if isinstance(m, dict) else None
            ts = str(e.get("timestamp") or "")
            if not u or not ts:
                continue
            mid = m.get("id") or e.get("uuid")  # Claude Code writes each reply more than once while streaming
            seen = d.setdefault("seen", {})
            if mid in seen:
                continue
            seen[mid] = ts[:10]
            day, model = ts[:10], m.get("model") or "?"
            c = d["days"].setdefault(day, {}).setdefault(model, {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "replies": 0})
            vals = {"input": u.get("input_tokens", 0), "output": u.get("output_tokens", 0),
                    "cache_read": u.get("cache_read_input_tokens", 0), "cache_write": u.get("cache_creation_input_tokens", 0)}
            for k, v in vals.items():
                c[k] += int(v or 0)
            c["replies"] += 1
            s["tokens"] += sum(int(v or 0) for v in vals.values())
            s["replies"] += 1
            s["model"] = model
            s["first"] = s["first"] or ts
            s["last"] = max(s["last"], ts)
        d["offsets"][path] = start + end
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - KEEP_DAYS * 86400))
    d["days"] = {k: v for k, v in d["days"].items() if k >= cutoff}
    d["seen"] = {k: v for k, v in d.get("seen", {}).items() if v >= cutoff}
    d["sessions"] = {k: v for k, v in d["sessions"].items() if (v.get("last") or v.get("first") or "9")[:10] >= cutoff}
    d["checked"] = time.time()
    jsonstore.save(LOCAL_CACHE, d, indent=None)
    return d


def where(s):
    """readable origin of a session"""
    p = s.get("project", "")
    path = "/" + p.lstrip("-").replace("-", "/") if p.startswith("-") else p
    if "scratchpad" in p or p.startswith("-tmp-"):
        path = "temporary"
    kind = {"cli": "Terminal", "sdk-cli": "Remote Control / headless"}.get(s.get("entry", ""), s.get("entry", "") or "–")
    return kind, path


def summary(days=14):
    """data for the page: daily totals (last n days), sessions, models"""
    d = _local()
    today = time.time()
    labels = [time.strftime("%Y-%m-%d", time.localtime(today - i * 86400)) for i in range(days - 1, -1, -1)]
    series, models = [], {}
    for day in labels:
        tot = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "replies": 0}
        for model, c in d["days"].get(day, {}).items():
            for k in tot:
                tot[k] += c.get(k, 0)
            mm = models.setdefault(model, {"tokens": 0, "replies": 0})
            mm["tokens"] += c["input"] + c["output"] + c["cache_read"] + c["cache_write"]
            mm["replies"] += c["replies"]
        series.append(dict(tot, day=day))
    sessions = []
    for sid, s in d["sessions"].items():
        if not s.get("replies"):
            continue  # no model call (e.g. a local /usage or /context of older versions)
        kind, path = where(s)
        sessions.append(dict(s, id=sid, kind=kind, path=path))
    sessions.sort(key=lambda x: x.get("last", ""), reverse=True)
    return {"series": series, "models": sorted(models.items(), key=lambda x: -x[1]["tokens"]), "sessions": sessions[:30],
            "today": series[-1] if series else {}, "checked": d.get("checked", 0)}
