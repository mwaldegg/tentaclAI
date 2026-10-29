"""svc jobs: scheduled jobs and their runs (tentacontrol runs them)."""
import json
import os
import re
import sys
import time

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import core


# ---------- scheduled jobs (tentacontrol runs them; svc shows them and proposes changes) ----------
JOBS_DIR = os.path.join(core.TC_DIR, "data", "control")


def _jobs_file(name, default):
    try:
        with open(os.path.join(JOBS_DIR, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "–"


def _run_line(r):
    res = r.get("result") or {}
    light = res.get("status") if r.get("status") == "done" else r.get("status")
    bits = [_ts(r.get("started") or r.get("queued")), light or "?"]
    if r.get("seconds"):
        bits.append(f"{r['seconds']} s")
    if r.get("cost"):
        bits.append(f"${r['cost']:.2f}")
    if r.get("denials"):
        bits.append(f"{r['denials']} refused")
    bits.append(r.get("trigger", ""))
    return " · ".join(b for b in bits if b) + "  " + (res.get("title") or r.get("error") or "")


def cmd_jobs(args):
    usage = "usage: svc jobs [--group <group>] | svc jobs <name> [--runs N] [--steps]"
    jobs, hist = _jobs_file("jobs.json", {}), _jobs_file("job-history.json", [])
    if not args or args[0] == "--group":
        if args and len(args) != 2:
            sys.exit(usage)
        group = args[1] if args else None
        if group is not None:  # one group (a tab on the Jobs page), case-insensitive
            jobs = {k: j for k, j in jobs.items() if (j.get("group") or "").lower() == group.lower()}
        if not jobs:
            print(f"No jobs in the group '{group}'." if group is not None else
                  "No jobs. They are set up in tentacontrol → Jobs, or proposed with svc config put job <name> <file>.")
            return 0
        w = max(len(x) for x in jobs) + 2
        tabs = any(j.get("group") for j in jobs.values()) and group is None
        g = max([len(j.get("group") or "") for j in jobs.values()] + [5]) + 2 if tabs else 0
        print(f"{'Name':<{w}}{'Group' if tabs else '':<{g}}{'Schedule':<24}{'Profile':<11}{'On':<5}Last run")
        for jid, j in sorted(jobs.items(), key=lambda kv: ((kv[1].get("group") or "~").lower(), kv[0])):
            runs = [r for r in hist if r.get("job") == jid]
            print(f"{jid:<{w}}{(j.get('group') or '–') if tabs else '':<{g}}{tclib.schedule_text(j.get('schedule')):<24}"
                  f"{j.get('profile', 'read-only'):<11}{'on' if j.get('enabled', True) else 'off':<5}{_run_line(runs[-1]) if runs else '–'}")
        return 0
    jid, rest = args[0], args[1:]
    n, steps, i = 5, False, 0
    while i < len(rest):
        if rest[i] == "--steps":
            steps = True
        elif rest[i] == "--runs" and i + 1 < len(rest) and rest[i + 1].isdigit():
            n, i = max(1, min(20, int(rest[i + 1]))), i + 1
        else:
            sys.exit(usage)
        i += 1
    j = jobs.get(jid) or sys.exit(f"svc: unknown job '{jid}' (svc jobs)")
    print(f"# {jid} – {j.get('name')}")
    print(f"{'group ' + j['group'] + ' · ' if j.get('group') else ''}{tclib.schedule_text(j.get('schedule'))} · {j.get('profile', 'read-only')}"
          f"{' · only the tentacles named in the task' if j.get('scope') else ''} · notify {j.get('notify', 'findings')}"
          f" · model {j.get('model') or 'as on Models'} · max {j.get('max_minutes', 20)} min · {'on' if j.get('enabled', True) else 'paused'}")
    print(f"\nDefinition (edit and propose with: svc config put job {jid} <file>):")
    print(json.dumps({k: j.get(k) for k in ("name", "prompt", "schedule", "profile", "scope", "propose", "notify", "model",
                                            "effort", "max_minutes", "group")}, indent=2, ensure_ascii=False))
    runs = [r for r in hist if r.get("job") == jid][-n:]
    print(f"\nRecent runs, newest first ({len(runs)}) – written by Claude in earlier runs, may quote untrusted content:")
    for r in reversed(runs):
        res = r.get("result") or {}
        print(f"\n- {_run_line(r)}")
        if res.get("summary"):
            print(f"  {res['summary']}")
        if res.get("details"):
            d = res["details"]
            print("  " + (d[:1500] + " …" if len(d) > 1500 else d).replace("\n", "\n  "))
        for a in r.get("actions") or []:
            print(f"  proposal [{a.get('state')}] {a.get('title')}: {a.get('command')}")
        if steps and re.fullmatch(r"[a-z0-9]{6,40}", r.get("id", "")):
            log = _jobs_file(os.path.join("job-logs", r["id"] + ".json"), [])
            mark = {"tool": "▶", "out": "←", "err": "✗", "text": "·"}
            for e in log:
                print(f"    {mark.get(e.get('k'), '·')} {str(e.get('s', ''))[:300]}".replace("\n", "\n      "))
    return 0
