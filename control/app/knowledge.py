"""What Claude learned, proposed by a scheduled job and applied by the user: notes of a service or system, or the site
rules (local/CLAUDE.md). A weakness of tentaclAI itself (target "product") is not written anywhere – the user can report
it as an issue, so it is fixed where it is, instead of living on as a workaround in the site rules. A job can't wait for an approval (nobody watches it) and a read-only one can't write – so it
proposes, and tentacontrol applies what the user picks, with a backup and the same size budget the cleanup job keeps.
"""
import glob
import json
import os
import re
import shutil
import time

import tclib

from . import claude_files, services_store, systems_store
from .config import SERVICES_DIR, STACK_DIR, SYSTEMS_DIR
from .envfile import read_env

TARGETS = ("service", "system", "site", "product")
OPS = ("add", "replace", "remove")
NOTE_MAX = 500          # characters of one note
SITE_MAX = 3000         # characters of one change to the site rules (the cleanup job may rewrite a whole section)
SITE_HEADING = "## Learned"
KEEP_BACKUPS = 5

SCHEMA = {"type": "array", "maxItems": 10,
          "description": "lasting facts learned in this run that a note doesn't say yet, or a note to fix or drop – leave out when there is none",
          "items": {"type": "object", "additionalProperties": False, "required": ["target", "op", "why"], "properties": {
              "target": {"type": "string", "enum": list(TARGETS),
                         "description": "service = one tentacle, system = a host and all its services, site = the whole "
                                        "installation (local/CLAUDE.md), product = a weakness of tentaclAI itself (a missing "
                                        "svc option, a misleading message, a bug) – reported to its developers in a public "
                                        "tracker, not written: then new and why in English, without host, service or "
                                        "user names of this site"},
              "name": {"type": "string", "description": "service or system name; product: the part (svc, tentacontrol, …); not for site"},
              "op": {"type": "string", "enum": list(OPS)},
              "old": {"type": "string", "description": "replace/remove: the exact current note (site: an exact passage)"},
              "new": {"type": "string", "description": "add/replace: the note, one line, short"},
              "why": {"type": "string", "description": "one line: what in this run shows it"},
              "repro": {"type": "string", "description": "product only: the command or step that shows it (<host> for names of this site)"},
              "actual": {"type": "string", "description": "product only: what happened – the message or result, short"},
              "expected": {"type": "string", "description": "product only: what should happen instead"}}}}


def budget(env=None):
    """the size budget of what Claude reads: site rules in KB (loaded into every request), notes per service or system"""
    env = read_env() if env is None else env

    def num(key, default):
        try:
            return max(1, int(env.get(key) or default))
        except ValueError:
            return default
    return {"local_kb": num("KNOWLEDGE_LOCAL_KB", 6), "notes": num("KNOWLEDGE_NOTES", 8)}


def _line(text, limit):
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]


def check(item):
    """a proposal from a run → a clean item ({target, name, op, old, new, why, state, flags}); state "refused" with
    a reason when it can't be applied as it is"""
    if not isinstance(item, dict):
        return None
    target, op = str(item.get("target", "")), str(item.get("op", ""))
    if target == "product":  # nothing to apply – a finding for tentaclAI's developers, kept short and on one line
        x = {"target": target, "name": _line(item.get("name"), 40), "op": "add", "old": "", "new": _line(item.get("new"), NOTE_MAX),
             "why": _line(item.get("why"), 300), "state": "proposed"}
        x.update({k: _line(item.get(k), 400) for k in ("repro", "actual", "expected") if _line(item.get(k), 400)})
        if not x["new"]:
            x.update(state="refused", output="nothing to report")
        return x
    site = target == "site"
    limit = SITE_MAX if site else NOTE_MAX
    clean = (lambda t: str(t or "").replace("\r\n", "\n").strip()[:limit]) if site else (lambda t: _line(t, limit))
    x = {"target": target, "name": "" if site else _line(item.get("name"), 41), "op": op, "old": clean(item.get("old")),
         "new": _line(item.get("new"), NOTE_MAX) if site and op == "add" else clean(item.get("new")),  # an add is one list line, not a new section
         "why": _line(item.get("why"), 300), "state": "proposed"}
    problem = None
    if target not in TARGETS or op not in OPS:
        problem = "unknown target or operation"
    elif not site and not services_store.NAME.match(x["name"]):
        problem = f"no {target} name"
    elif not site and not os.path.exists(os.path.join(SERVICES_DIR if target == "service" else SYSTEMS_DIR, f"{x['name']}.json")):
        problem = f"unknown {target} {x['name']}"
    elif op in ("add", "replace") and not x["new"]:
        problem = "nothing to add"
    elif op in ("replace", "remove") and not x["old"]:
        problem = "which note? (old is empty)"
    if problem:
        x.update(state="refused", output=problem)
    flags = [r for r, _ in tclib.injection_findings(x["new"])] if x["new"] else []
    if flags:  # a note is read in every later session – text that instructs an AI must not slip in unnoticed
        x["flags"] = flags
    return x


def _backup(path):
    if os.path.exists(path):
        shutil.copy2(path, f"{path}.bak-{time.strftime('%Y-%m-%d-%H%M%S')}")
        for bak in sorted(glob.glob(path + ".bak-*"))[:-KEEP_BACKUPS]:
            os.remove(bak)


def _notes(notes, x):
    notes = [n for n in notes if isinstance(n, str)]
    if x["op"] == "add":
        if x["new"] in notes:
            raise ValueError("already there")
        return notes + [x["new"]]
    if x["old"] not in notes:
        raise ValueError("the note changed since the run – not applied")
    i = notes.index(x["old"])
    return notes[:i] + ([x["new"]] if x["op"] == "replace" else []) + notes[i + 1:]


def _site(text, x):
    if x["op"] == "add":
        if x["new"] in text:
            raise ValueError("already there")
        line = "- " + x["new"].lstrip("- ")
        if SITE_HEADING in text.splitlines():
            return text.rstrip("\n") + "\n" + line + "\n"
        return text.rstrip("\n") + f"\n\n{SITE_HEADING}\n\n{line}\n"
    if text.count(x["old"]) != 1:
        raise ValueError("the passage changed since the run (or is not unique) – not applied")
    out = text.replace(x["old"], x["new"] if x["op"] == "replace" else "")
    return re.sub(r"\n{3,}", "\n\n", out)


def issue_url(x, version="", repo=None, run=None, edition=""):
    """a prefilled "new issue" link for a product finding – the user reviews it on GitHub before anything is sent"""
    from urllib.parse import quote
    repo = repo or (read_env().get("UPDATE_REPO") or "mwaldegg/tentaclai").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        repo = "mwaldegg/tentaclai"
    part = f"{x['name']}: " if x.get("name") else ""
    run, env = run or {}, (run or {}).get("env") or {}
    found = f"job run, {time.strftime('%Y-%m-%d', time.localtime(run['queued']))}" if run.get("queued") else "job run"
    lines = [x["new"], ""]
    for label, key in (("Steps / command", "repro"), ("Actual", "actual"), ("Expected", "expected")):
        if x.get(key):
            lines.append(f"**{label}:** {x[key]}" if key != "repro" else f"**{label}:** `{x[key]}`")
    lines += [f"**How it showed:** {x.get('why') or '–'}", "", "**Environment**",
              f"- tentaclAI: {version or '?'}{' ' + edition if edition else ''}",
              f"- Claude Code: {env.get('claude_code') or '?'}" + (f" · model {env['model']}" if env.get("model") else ""),
              f"- Part: {x.get('name') or '?'}",
              f"- Found by: {found}" + (f" (profile {run['profile']})" if run.get("profile") else ""), "",
              "_Check for host names or other site details before you submit._"]
    body = "\n".join(lines)
    return f"https://github.com/{repo}/issues/new?title={quote(part + issue_title(x['new']))}&body={quote(body)}"


def issue_title(text, limit=80):
    """the first sentence (e.g., i.e., etc. and vs. don't end it), cut at a word – not mid-word with a dangling comma"""
    first = re.split(r"(?<![\s(]e\.g\.)(?<![\s(]i\.e\.)(?<!\betc\.)(?<!\bvs\.)(?<=[.!?])\s", text, maxsplit=1)[0].rstrip(".")
    if len(first) <= limit:
        return first
    return first[:limit].rsplit(" ", 1)[0].rstrip(",;:–- ") + " …"


def apply(x):
    """write one checked proposal (raises ValueError) → a short description of what changed"""
    if x.get("state") != "proposed":
        raise ValueError("not open")
    if x["target"] == "product":
        raise ValueError("a finding for tentaclAI is reported, not applied")
    if x["target"] == "site":
        old = claude_files.read_local() if os.path.exists(claude_files.LOCAL) else ""
        claude_files.save_local(_site(old, x))  # keeps its own backups
        return f"site rules: {x['op']}"
    if x["target"] == "service":
        data = json.loads(services_store.read_raw(x["name"]))
        data["notes"] = _notes(data.get("notes") or [], x)
        _backup(services_store.path_of(x["name"]))
        services_store.save_raw(x["name"], json.dumps(data, ensure_ascii=False))
    else:
        data = systems_store.get(x["name"])
        data["notes"] = _notes(data.get("notes") or [], x)
        _backup(systems_store.path_of(x["name"]))
        systems_store.save_raw(x["name"], data)
    return f"{x['target']} {x['name']}: note {x['op']}"


def sizes(env=None):
    """the knowledge Claude reads, against the budget: site rules (KB) and notes per service and system"""
    b = budget(env)
    try:
        local = len(claude_files.read_local().encode()) if os.path.exists(claude_files.LOCAL) else 0
    except OSError:
        local = 0
    over = []
    for kind, data in (("service", tclib.load_services(SERVICES_DIR)), ("system", tclib.load_systems(STACK_DIR))):
        for name, d in sorted(data.items()):
            n = len(d.get("notes") or [])
            if n > b["notes"]:
                over.append({"kind": kind, "name": name, "notes": n})
    return {"budget": b, "local_kb": round(local / 1024, 1), "local_over": local > b["local_kb"] * 1024, "over": over}
