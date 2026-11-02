"""svc config put: service and system files, site rules, site skills and jobs – always with approval and a diff."""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import catalog, core, gate, safeguards, ssh_part


def cmd_config(services, args):
    """Claude proposes a service or system file, the site rules or a job; the user approves every write (the stack dir
    is root's) and sees the changes in the approval"""
    if len(args) >= 4 and args[0] == "put" and args[1] == "job":
        return config_put_job(args[2], args[3])
    kind = args[1] if len(args) >= 3 and args[0] == "put" else ""
    if kind not in ("service", "system", "local", "skill") or (kind != "local" and len(args) < 4):
        sys.exit("usage: svc config put service <name> <file>  |  put system <name> <file>  |  put local <file>  |  "
                 "put skill <name> <file>  |  put job <name> <file>")
    if core.job_read_only():
        sys.exit("svc: a read-only job can't propose configuration changes")
    if kind == "local":
        name, src = "local", args[2]
        target = os.path.join(core.TC_DIR, "local", "CLAUDE.md")
    elif kind == "skill":
        name, src = args[2], args[3]
        target = os.path.join(core.SKILLS_DIR, name, "SKILL.md")
    else:
        name, src = args[2], args[3]
        if not tclib.valid_name(name):
            sys.exit(f"svc: {kind} names: a-z 0-9 _ - (max 41)")
        target = os.path.join(core.SERVICES_DIR if kind == "service" else core.SYSTEMS_DIR, f"{name}.json")
    section = {"service": "services", "system": "systems", "local": "instructions", "skill": "skills"}[kind]
    central = tclib.central_locked(gate.AUDIT_DIR, section, name)
    if central:
        sys.exit(f"svc: {kind} {name} is managed by {central} – it can only be changed there")
    r = subprocess.run(["cat", "--", src], capture_output=True, **core.as_user(core.CLAUDE_USER))  # read with Claude's rights
    if r.returncode != 0:
        sys.exit(f"svc: can't read {src}: {r.stderr.decode(errors='replace').strip()[:160]}")
    text = r.stdout.decode("utf-8", "replace")
    if len(text) > 512 * 1024:
        sys.exit("svc: file too large")
    old = open(target).read() if os.path.exists(target) else None
    if kind == "service":
        data = config_json(text, "service")
        access = ", ".join(f"{p} {data[p].get('access', '–')}" for p in core.PARTS if isinstance(data.get(p), dict)) or "no parts"
        action = f"{'change' if old is not None else 'create'} services/{name}.json ({access})"
    elif kind == "system":
        data = config_json(text, "system")
        problem = system_problem(data)
        if problem:
            sys.exit(f"svc: {problem}")
        text = json.dumps({"name": name, **{k: v for k, v in data.items() if k != "name"}}, ensure_ascii=False, indent=2) + "\n"
        action = f"{'change' if old is not None else 'create'} systems/{name}.json"
    elif kind == "skill":
        text = text.replace("\r\n", "\n")
        problem = tclib.site_skill_problem(name, text)
        if problem:
            sys.exit(f"svc: {problem}")
        action = f"{'change' if old is not None else 'create'} skill {name} ({len(text.splitlines())} lines)"
    else:
        action = f"{'change' if old is not None else 'create'} local/CLAUDE.md ({len(text.splitlines())} lines)"
    if old == text:
        print("unchanged")
        return 0
    diff, added = config_diff(old, text, json_file=kind in ("service", "system"))
    if old is not None:
        action += f", +{len(added)}/-{sum(1 for ln in diff.splitlines() if ln.startswith('-'))} lines"
    findings = tclib.injection_findings("\n".join(added)) if safeguards.guard_on() else []
    if findings:  # what Claude wants to keep for every later session reads like an instruction to an AI
        safeguards.guard_note("configuration change", f"{kind} {name}" if kind in ("system", "skill") else name, "config", action, findings)

    def write():
        if old is not None:
            shutil.copy2(target, f"{target}.bak-{time.strftime('%Y-%m-%d-%H%M%S')}")
            for bak in sorted(glob.glob(target + ".bak-*"))[:-5]:  # the last 5 versions are enough
                os.remove(bak)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if kind == "skill":  # readable for Claude like the other files here (svc's umask is 077)
            for d in (core.SKILLS_DIR, os.path.dirname(target)):
                os.chmod(d, 0o755)
        with open(target + ".tmp", "w") as f:
            f.write(text)
        os.chmod(target + ".tmp", 0o644)  # Claude reads them (local: @import) – svc's inherited umask is 077; no secrets in them
        os.replace(target + ".tmp", target)
        print(f"✓ {os.path.relpath(target, core.TC_DIR)} written" + (" (previous version kept as .bak-…)" if old is not None else ""))
        if kind == "local":
            catalog.write_instructions()
        elif kind == "skill":
            catalog.sync_skills()
        else:
            catalog.cmd_sync(core.load())  # catalog and instructions show service and system notes
        return 0
    return gate.guarded(f"{kind} {name}" if kind in ("system", "skill") else name, "config", "confirm", action, write,
                   review={"diff": diff, "flags": [r for r, _ in findings]})


def config_json(text, kind):
    try:
        data = json.loads(text)
    except ValueError as e:
        sys.exit(f"svc: invalid JSON: {e}")
    if not isinstance(data, dict):
        sys.exit(f"svc: a {kind} file is a JSON object")
    return data


def system_problem(data):
    """why a system file can't be written – None if it is fine (members join through the services' "system" field)"""
    extra = set(data) - ssh_part.SYSTEM_KEYS
    if extra:
        return f"unknown fields in a system: {', '.join(sorted(extra))} (allowed: description, ssh_host, notes)"
    if not isinstance(data.get("description", ""), str) or not isinstance(data.get("ssh_host", ""), str):
        return "description and ssh_host are text"
    if not isinstance(data.get("notes", []), list) or not all(isinstance(n, str) for n in data.get("notes", [])):
        return "notes is a list of texts"
    if data.get("ssh_host") and not tclib.ssh_host(core.SSH_CONF_D, data["ssh_host"]):
        return f"unknown SSH host '{data['ssh_host']}' (svc ssh lists them)"
    return None


def config_diff(old, new, json_file=False):
    """(diff for the approval, added lines): JSON compared in one layout and without the commas at line ends – a file
    written in another style, or a note appended to a list, shows only what really changed; secrets blanked, cut to
    REVIEW_DIFF"""
    import difflib

    def lines(t):
        if t is None:
            return []
        if json_file:
            try:
                return [ln.rstrip(",") for ln in json.dumps(json.loads(t), ensure_ascii=False, indent=2).splitlines()]
            except ValueError:
                pass
        return t.splitlines()
    a, b = lines(old), lines(new)
    out = [ln for ln in difflib.unified_diff(a, b, lineterm="", n=1) if not ln.startswith(("---", "+++"))]
    added = [ln[1:] for ln in out if ln.startswith("+")]
    text = safeguards._redact_text("\n".join(out))
    return (text[:ssh_part.REVIEW_DIFF] + "\n…" if len(text) > ssh_part.REVIEW_DIFF else text), added


def config_put_job(name, src):
    """propose a job: tentacontrol checks it (same rules as the editor), the user approves, tentacontrol saves it –
    a new job starts paused"""
    if core.job():
        sys.exit("svc: a scheduled job can't create or change jobs")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", name):
        sys.exit("svc: job names: a-z 0-9 - (max 41)")
    r = subprocess.run(["cat", "--", src], capture_output=True, **core.as_user(core.CLAUDE_USER))  # read with Claude's rights
    if r.returncode != 0:
        sys.exit(f"svc: can't read {src}: {r.stderr.decode(errors='replace').strip()[:160]}")
    if len(r.stdout) > 64 * 1024:
        sys.exit("svc: file too large")
    try:
        d = json.loads(r.stdout.decode("utf-8", "replace"))
    except ValueError as e:
        sys.exit(f"svc: invalid JSON: {e}")
    try:
        chk = gate._control("POST", "/internal/jobs/check", {"name": name, "definition": d}, timeout=20)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"svc: tentacontrol not reachable: {e}")
    if chk.get("errors"):
        sys.exit("svc: not a valid job – " + "; ".join(chk["errors"]))
    for w in chk.get("warnings") or []:
        print(f"note: {w}")

    def write():
        try:
            res = gate._control("POST", "/internal/jobs/put", {"name": name, "definition": d}, timeout=20)
        except Exception as e:  # noqa: BLE001
            print(f"✗ tentacontrol: {e}")
            return 1
        print(f"✓ job {res.get('id')} saved – {'on' if res.get('enabled') else 'paused: switch it on in tentacontrol → Jobs'}")
        return 0
    return gate.guarded(f"job {name}", "config", "confirm", chk.get("summary") or f"job {name}", write)
