"""Export / import of the configuration: services, systems, SSH hosts, jobs, network rules, notifications, site rules,
site skills and plain settings – as one JSON file. Secrets never leave .env: the file only names the ${VAR}s the next installation needs.

Import is two steps: preview() compares the file with this installation (nothing is written), apply() writes the
entries picked in the preview through the same functions the UI uses – a file that gets overwritten keeps a .bak."""
import difflib
import glob
import hashlib
import json
import os
import shutil
import time

import tclib

from . import claude_files, egress, extensions, jsonstore, notify, scheduled, services_store, skills, sshhosts, systems_store
from .central import check_write
from .config import DATA_DIR, SERVICES_DIR, SETTINGS_GROUPS, STACK_DIR, SYSTEMS_DIR, is_secret
from .envfile import read_env, update_env
from .log import get

log = get("backup")

FORMAT, VERSION = "tentaclai-export", 1
MAX_SIZE = 2 * 1024 * 1024
PENDING = os.path.join(DATA_DIR, "import-pending.json")
PENDING_TTL = 3600
# section → label; also the order of import (SSH hosts and systems before the services that use them, jobs after them)
SECTIONS = {
    "ssh_hosts": "SSH hosts", "systems": "Systems", "services": "Services", "jobs": "Jobs", "network": "Network rules",
    "notifications": "Notifications", "instructions": "Site rules (local/CLAUDE.md)", "skills": "Site skills (local/skills)",
    "settings": "Settings",
}
# picked in the preview only on request: they change how Claude works or what this installation is
OPT_IN = {"instructions", "skills", "settings"}
EXT_PREFIX = "x_"  # parts of extensions (add_backup_part): x_<extension>_<key>, always opt-in


def sections():
    """SECTIONS plus the parts of the active extensions"""
    out = dict(SECTIONS)
    for sid, p in extensions.backup_parts().items():
        out[sid] = f"{p['label']} ({extensions.title(p['ext'])})"
    return out


SSH_FIELDS = ("alias", "hostname", "user", "port", "proxyjump", "hostkeyalias", "sudo", "access")
SKIP_GROUPS = {"Paths & mounts"}  # host specific
CHANNEL_KINDS = {"ntfy", "webhook", "email", "apprise"}


def _version():
    try:
        with open(os.path.join(os.path.dirname(SERVICES_DIR), "VERSION")) as f:
            return f.read().strip()
    except OSError:
        return "dev"


def _strip(data):
    return {k: v for k, v in data.items() if k != "name"}


def _raw_dir(path):
    """name → parsed JSON of path/*.json without templates/examples and broken files"""
    out = {}
    for p in sorted(glob.glob(os.path.join(path, "*.json"))):
        base = os.path.basename(p)[:-5]
        if base.startswith("_"):
            continue
        try:
            data = json.load(open(p))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            out[base] = _strip(data)
    return out


def setting_keys():
    return [k for group, items in SETTINGS_GROUPS if group not in SKIP_GROUPS for k, _, _, kind in items
            if kind != "readonly" and not is_secret(k)]


def _job_def(job):
    return {k: v for k, v in scheduled.definition(job).items() if v is not None}


def _notifications():
    c = notify.load()
    return {"channels": [{k: ch.get(k) for k in ("id", "name", "kind", "enabled")} for ch in c["channels"]],
            "routes": c["routes"], "quiet": c["quiet"], "dedupe_min": c["dedupe_min"]}


# ---------------------------------------------------------------- export

def export(parts=None):
    """the export document and the plain secrets that were left out (service, key path) – shown before the download"""
    known = sections()
    parts = [p for p in (parts or known) if p in known]
    env = read_env()
    doc = {"format": FORMAT, "version": VERSION, "tentaclai": _version(), "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "host": env.get("TC_HOSTNAME", "")}
    left_out = []
    if "services" in parts:
        services = _raw_dir(SERVICES_DIR)
        for name, data in services.items():
            for path in tclib.literal_secrets(data):
                left_out.append((name, ".".join(str(k) for k in path)))
                services_store._blank(data, path)
        doc["services"] = services
    if "systems" in parts:
        doc["systems"] = _raw_dir(SYSTEMS_DIR)
    if "ssh_hosts" in parts:
        doc["ssh_hosts"] = [{k: h.get(k, "") for k in SSH_FIELDS} for h in sshhosts.hosts()]
    if "jobs" in parts:
        doc["jobs"] = {jid: dict(_job_def(j), enabled=bool(j.get("enabled"))) for jid, j in sorted(scheduled.load().items())}
    if "network" in parts:
        doc["network"] = egress.rules()
    if "notifications" in parts:
        doc["notifications"] = _notifications()
    if "instructions" in parts:
        doc["instructions"] = claude_files.read_local()
    if "skills" in parts:
        doc["skills"] = {name: skills.site_text(name) for name in tclib.site_skills(STACK_DIR)}
    if "settings" in parts:
        doc["settings"] = {k: env[k] for k in setting_keys() if env.get(k)}
    for sid, p in extensions.backup_parts().items():
        if sid in parts:
            try:
                doc[sid] = p["export"]()
            except Exception as e:  # noqa: BLE001 – an extension's part must not break the export
                log.warning(f"extension {p['ext']}: backup export: {e}")
    needed = set()
    for data in doc.get("services", {}).values():
        needed |= tclib.variables({k: v for k, v in data.items() if k in tclib.PARTS})
    needed |= {notify.env_key(ch["id"]) for ch in doc.get("notifications", {}).get("channels", [])}
    doc["variables"] = sorted(needed)
    return doc, left_out


def literal_secrets():
    """(service, key path) of plain values in credential fields – an export leaves them out"""
    return [(n, ".".join(str(k) for k in p)) for n, d in _raw_dir(SERVICES_DIR).items() for p in tclib.literal_secrets(d)]


# ---------------------------------------------------------------- import: parse, keep, preview

def parse(raw):
    if len(raw) > MAX_SIZE:
        raise ValueError("file too large (max. 2 MB)")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("not a JSON file")
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValueError("not a tentaclAI export")
    if doc.get("version") != VERSION:
        raise ValueError(f"export format version {doc.get('version')} – this tentaclAI reads version {VERSION}")
    unknown = {k for k in set(doc) - set(SECTIONS) - {"format", "version", "tentaclai", "created", "host", "variables"}
               if not k.startswith(EXT_PREFIX)}  # an extension's part: checked in the preview
    if unknown:
        raise ValueError(f"unknown parts: {', '.join(sorted(unknown))}")
    types = {"services": dict, "systems": dict, "ssh_hosts": list, "jobs": dict, "network": dict, "notifications": dict,
             "instructions": str, "skills": dict, "settings": dict, "variables": list}
    for k, t in types.items():
        if k in doc and not isinstance(doc[k], t):
            raise ValueError(f"{k}: wrong type")
    return doc


def keep(doc):
    """the uploaded file until apply – root only, expires after an hour"""
    jsonstore.save(PENDING, {"ts": time.time(), "doc": doc}, indent=None, mode=0o600)


def pending():
    p = jsonstore.load(PENDING)
    if not p or time.time() - p.get("ts", 0) > PENDING_TTL:
        return None
    return p.get("doc")


def drop_pending():
    try:
        os.remove(PENDING)
    except FileNotFoundError:
        pass


def _dump(v):
    return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, indent=2, sort_keys=True)


def _diff(old, new):
    a, b = _dump(old).splitlines(), _dump(new).splitlines()
    return "\n".join(list(difflib.unified_diff(a, b, "this installation", "import", n=2, lineterm=""))[2:])


def _hash(v):
    return "" if v is None else hashlib.sha256(_dump(v).encode()).hexdigest()[:16]


def _row(section, key, old, new, error="", note="", label=None):
    if error:
        status = "invalid"
    elif old is None:
        status = "new"
    elif old == new:
        status = "same"
    else:
        status = "changed"
    return {"section": section, "key": key, "id": f"{section}:{key}", "label": label or key, "status": status,
            "error": error, "note": note, "diff": _diff(old, new) if status == "changed" else "",
            "hash_old": _hash(old), "hash_new": _hash(new),  # central management: which value was applied
            "checked": status in ("new", "changed") and section not in OPT_IN and not section.startswith(EXT_PREFIX)}


def _access_note(data):
    modes = [f"{p} {tclib.access(data[p].get('access'), tclib.part_default(p))}"
             for p in tclib.PARTS if isinstance(data.get(p), dict) and p != "mcp"]
    return ", ".join(modes)


def preview(doc):
    """section → rows {id, label, status new/changed/same/invalid, error, note, diff, checked} – nothing is written"""
    known = sections()
    rows = {s: [] for s in list(known) + sorted(k for k in doc if k.startswith(EXT_PREFIX) and k not in known) if s in doc}
    services = _raw_dir(SERVICES_DIR)
    for data in services.values():
        tclib.migrate_access(data)  # a file still saying ro/rw is not "changed" by the same file in read/write
    hosts = {h["alias"]: {k: h.get(k, "") for k in SSH_FIELDS} for h in sshhosts.hosts()}
    for h in doc.get("ssh_hosts", []):
        alias = h.get("alias", "") if isinstance(h, dict) else ""
        err = ""
        try:
            if not isinstance(h, dict) or set(h) - set(SSH_FIELDS):
                raise ValueError(f"only the fields {', '.join(SSH_FIELDS)}")
            fields = {k: str(h.get(k) or "") for k in SSH_FIELDS}
            fields["port"] = fields["port"] or "22"
            fields["access"] = tclib.access(fields["access"], tclib.SSH_ACCESS_DEFAULT)
            tclib.ssh_validate(fields)
            if fields["hostkeyalias"] and not tclib.HOST_RE.match(fields["hostkeyalias"]):
                raise ValueError("HostKeyAlias: a DNS name")
        except ValueError as e:
            err, fields = str(e), h
        rows["ssh_hosts"].append(_row("ssh_hosts", alias or "?", hosts.get(alias), fields, err,
                                      note="" if err else f"{fields['user']}@{fields['hostname']}, ssh {fields['access']}"))
    systems = _raw_dir(SYSTEMS_DIR)
    for name, data in doc.get("systems", {}).items():
        err = "" if services_store.NAME.match(name) and isinstance(data, dict) else "invalid name or not a JSON object"
        rows["systems"].append(_row("systems", name, systems.get(name), _strip(data) if not err else data, err))
    for name, data in doc.get("services", {}).items():
        err = ""
        if not services_store.NAME.match(name):
            err = "name: lowercase letters, digits, - and _"
        elif not isinstance(data, dict):
            err = "not a JSON object"
        else:
            data = _strip(data)
            tclib.migrate_access(data)
        rows["services"].append(_row("services", name, services.get(name), data, err,
                                     note="" if err else _access_note(data)))
    # @mentions in jobs may name tentacles that come with this import
    known = scheduled.tentacles()
    for name, data in doc.get("services", {}).items():
        known.setdefault(name, {"kind": "service", "parts": {}, "enabled": True})
    for h in doc.get("ssh_hosts", []):
        if isinstance(h, dict) and h.get("alias"):
            known.setdefault(h["alias"], {"kind": "ssh", "parts": {}, "enabled": True})
    jobs = scheduled.load()
    for jid, d in doc.get("jobs", {}).items():
        err, new = "", d
        try:
            if not scheduled.ID_RE.match(jid) or jid in scheduled.RESERVED:
                raise ValueError("job name: a-z 0-9 - (max 41), not new/save/runs")
            if not isinstance(d, dict):
                raise ValueError("a job is a JSON object")
            new = {k: v for k, v in d.items() if k != "enabled"}
            scheduled.validate(scheduled.form_from_definition(new), known)
        except ValueError as e:
            err = str(e)
        old = _job_def(jobs[jid]) if jid in jobs else None
        note = "" if err else f"{scheduled.describe(new.get('schedule') or {'kind': 'manual'})}, {new.get('profile') or 'read-only'}"
        if not err and old is None:
            note += " – added paused"
        rows["jobs"].append(_row("jobs", jid, old, _job_def(new) if not err else new, err, note=note,
                                 label=f"{jid} ({new.get('name', '')})" if isinstance(new, dict) else jid))
    if "network" in doc:
        cur = egress.rules()
        for kind in ("allow", "block"):
            entries = doc["network"].get(kind, [])
            for e in entries if isinstance(entries, list) else []:
                err = ""
                try:
                    e = egress.normalize(str(e))
                except ValueError as x:
                    err = str(x)
                other = "block" if kind == "allow" else "allow"
                old = kind if e in cur[kind] else (other if e in cur[other] else None)
                rows["network"].append(_row("network", f"{kind}:{e}", old, kind, err, label=f"{kind}  {e}",
                                            note=f"moves from the {other}list" if old == other else ""))
    if "notifications" in doc:
        n = doc["notifications"]
        cur = _notifications()
        have = {ch["id"]: ch for ch in cur["channels"]}
        for ch in n.get("channels", []) if isinstance(n.get("channels"), list) else []:
            err = ""
            if not isinstance(ch, dict) or not notify.ID_RE.match(str(ch.get("id", ""))):
                err = "invalid channel id"
            elif ch.get("kind") not in CHANNEL_KINDS:
                err = f"unknown kind {ch.get('kind')!r}"
            cid = str(ch.get("id", "?")) if isinstance(ch, dict) else "?"
            new = {"id": cid, "name": str(ch.get("name") or cid), "kind": ch.get("kind")} if not err else ch
            old = {k: have[cid][k] for k in ("id", "name", "kind")} if cid in have else None
            rows["notifications"].append(_row("notifications", f"channel:{cid}", old, new, err, label=f"channel {cid}",
                                              note="" if err or old else f"added disabled – its URL goes to {notify.env_key(cid)}"))
        rules = {k: n[k] for k in ("routes", "quiet", "dedupe_min") if k in n}
        if rules:
            err = ""
            routes = rules.get("routes", {})
            if not isinstance(routes, dict) or set(routes) - set(notify.EVENTS):
                err = "unknown events in the routes"
            elif not all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in routes.values()):
                err = "a route is a list of channel ids"
            elif not isinstance(rules.get("quiet", {}), dict) or not isinstance(rules.get("dedupe_min", 0), int):
                err = "invalid quiet hours or dedupe"
            old = {k: cur[k] for k in rules}
            rows["notifications"].append(_row("notifications", "rules", old, rules, err, label="routes, quiet hours, dedupe",
                                              note="routes to channels that don't exist here are dropped"))
    if "instructions" in doc:
        text = doc["instructions"]
        cur = claude_files.read_local()
        err = "file too large" if len(text.encode()) > claude_files.MAX_SIZE else ""
        rows["instructions"].append(_row("instructions", "local", cur if cur or not text else None, text if not text or text.endswith("\n") else text + "\n",
                                         err, label="local/CLAUDE.md", note="instructions for Claude – read them before you import"))
    for name, text in doc.get("skills", {}).items():
        err = "a SKILL.md is text" if not isinstance(text, str) else tclib.site_skill_problem(name, text.replace("\r\n", "\n")) or ""
        cur = skills.site_text(name) if name in tclib.site_skills(STACK_DIR) else None
        flags = [r for r, _ in tclib.injection_findings(text)] if not err else []
        note = "" if err else (tclib.skill_front(text).get("description", "")[:160] +
                               (f" – ⚠ {', '.join(flags)}" if flags else "") + " – steps Claude follows: read them before you import")
        rows["skills"].append(_row("skills", name, cur, text.replace("\r\n", "\n") if not err else text, err, note=note))
    if "settings" in doc:
        env = read_env()
        allowed = set(setting_keys())
        for k, v in doc["settings"].items():
            err = "" if k in allowed else "not an importable setting (secrets and host paths stay out)"
            if not err and (not isinstance(v, str) or "\n" in v):
                err = "a one-line text value"
            rows["settings"].append(_row("settings", k, env.get(k) or None, v, err))
    parts = extensions.backup_parts()
    for sid in [k for k in rows if k.startswith(EXT_PREFIX)]:
        if sid not in parts:
            rows[sid].append(_row(sid, "data", None, doc[sid], "the extension of this part isn't installed or enabled here",
                                  label=sid))
            continue
        try:
            cur = parts[sid]["export"]()
        except Exception:  # noqa: BLE001
            cur = None
        rows[sid].append(_row(sid, "data", cur, doc[sid], "", label="all of it", note="replaces what the extension has"))
    return rows


# ---------------------------------------------------------------- import: apply

def _backup(path, stamp):
    if os.path.exists(path):
        shutil.copy2(path, f"{path}.bak-{stamp}-import")


def apply(doc, picked):
    """write the picked rows (ids from preview) – returns (results, missing variables); results: {id, label, ok, msg}"""
    rows = preview(doc)
    stamp = time.strftime("%Y-%m-%d-%H%M%S")
    results = []
    known = sections()
    todo = [r for s in rows for r in rows[s] if r["id"] in picked and r["status"] in ("new", "changed")]

    def done(r, msg, ok=True):
        results.append({"id": r["id"], "label": r["label"], "section": known.get(r["section"], r["section"]), "ok": ok, "msg": msg})

    jobs_saved = False
    for r in todo:
        sec, key = r["section"], r["key"]
        try:
            if sec == "ssh_hosts":
                h = next(x for x in doc["ssh_hosts"] if isinstance(x, dict) and x.get("alias") == key)
                fields = {k: str(h.get(k) or "") for k in SSH_FIELDS}
                fields["port"] = fields["port"] or "22"
                if r["status"] == "new":
                    sshhosts.add(fields)
                else:
                    f = os.path.join(sshhosts.CONF_D, sshhosts.get(key)["file"])
                    _backup(f, stamp)
                    sshhosts.update(key, fields)
            elif sec == "systems":
                _backup(systems_store.path_of(key), stamp)
                systems_store.save_raw(key, doc["systems"][key])
            elif sec == "services":
                _backup(services_store.path_of(key), stamp)
                services_store.save_raw(key, json.dumps(_strip(doc["services"][key]), ensure_ascii=False))
            elif sec == "jobs":
                if not jobs_saved:
                    _backup(scheduled.JOBS, stamp)
                    jobs_saved = True
                d = doc["jobs"][key]
                from .central import is_applying  # a job from the central server starts as it says (default: on), an import paused
                scheduled.put(key, {k: v for k, v in d.items() if k != "enabled"}, enabled=is_applying() and d.get("enabled", True) is not False)
            elif sec == "network":
                kind, _, entry = key.partition(":")
                if r["status"] == "changed":
                    _backup(egress.RULES, stamp)
                egress.add(kind, entry)
            elif sec == "notifications":
                check_write("notifications", key)  # notify.save takes the whole file – the lock is per item
                _backup(notify.CONFIG, stamp)
                c = notify.load()
                if key.startswith("channel:"):
                    cid = key.split(":", 1)[1]
                    ch = next(x for x in doc["notifications"]["channels"] if isinstance(x, dict) and x.get("id") == cid)
                    cur = next((x for x in c["channels"] if x["id"] == cid), None)
                    if cur:
                        cur.update(name=str(ch.get("name") or cid), kind=ch["kind"])
                    else:
                        c["channels"].append({"id": cid, "name": str(ch.get("name") or cid), "kind": ch["kind"], "enabled": False})
                else:
                    n = doc["notifications"]
                    ids = {x["id"] for x in c["channels"]}
                    if "routes" in n:
                        c["routes"] = {ev: [x for x in n["routes"].get(ev, []) if x in ids] for ev in notify.EVENTS}
                    if "quiet" in n:
                        q = n["quiet"]
                        c["quiet"] = {"enabled": bool(q.get("enabled")), "from": str(q.get("from", "23:00")), "to": str(q.get("to", "07:00"))}
                    if "dedupe_min" in n:
                        c["dedupe_min"] = max(0, min(int(n["dedupe_min"]), 1440))
                notify.save(c)
            elif sec == "instructions":
                claude_files.save_local(doc["instructions"])  # keeps its own .bak
            elif sec == "skills":
                skills.save_site(key, doc["skills"][key])  # keeps its own .bak
            elif sec == "settings":
                update_env({key: doc["settings"][key]})
            elif sec.startswith(EXT_PREFIX):
                extensions.backup_parts()[sec]["apply"](doc[sec])
            done(r, "added" if r["status"] == "new" else "updated")
        except (ValueError, OSError, KeyError, StopIteration, TypeError, AttributeError) as e:  # one malformed part, not the whole import
            done(r, str(e) or "not found", ok=False)
    return results, missing(doc)


def missing(doc):
    """variables the imported configuration uses that are still empty in .env"""
    env = read_env()
    used = set(doc.get("variables") or []) | {notify.env_key(ch["id"]) for ch in notify.load()["channels"]}
    for data in _raw_dir(SERVICES_DIR).values():
        used |= tclib.variables({k: v for k, v in data.items() if k in tclib.PARTS})
    names = [v for v in used if isinstance(v, str) and tclib.VAR.fullmatch("${" + v + "}")]
    return sorted(v for v in names if not env.get(v))
