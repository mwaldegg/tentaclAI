"""Access to a tentacle: the lookup with a job's limit (get, get_part), the access mode, the audit log and approvals –
every write goes through guarded(): audit first (fail closed), then the approval in tentacontrol, then the result."""
import json
import os
import re
import sys
import time

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import core, safeguards


def require_allowed(name):
    if not core.job_allows(name):
        audit(name, "job", "–", "use", "blocked", detail="tentacle not in job")
        sys.exit(f"svc: this job may only use the tentacles its task names ({', '.join(sorted(core.job()['allow'])) or 'none'}) – not {name}")


def get(services, name):
    svc = services.get(name) or sys.exit(f"svc: unknown service '{name}' (svc list)")
    require_allowed(name)
    return svc


def get_part(services, name, part):
    svc = get(services, name)
    if part not in svc:
        sys.exit(f"svc: {name} has no {part} part")
    if not core.enabled(svc):
        sys.exit(f"svc: {name} is disabled")
    miss = core.missing_vars(svc[part])
    if miss:
        sys.exit(f"svc: {name} not enabled – empty in .env: {', '.join(miss)}")
    return core.render(svc[part])


def cmd_pending(args):
    """approvals waiting in tentacontrol – `--json` for the status line (count, link, oldest request)"""
    try:
        data = _control("GET", "/internal/approvals", timeout=3)
    except Exception as e:  # noqa: BLE001
        if "--json" in args:
            print(json.dumps({"error": str(e)[:120]}))
            return 1
        sys.exit(f"svc: tentacontrol not reachable: {e}")
    url = (core.ENV.get("CONTROL_URL") or "").rstrip("/")
    pending, grants = data.get("pending", []), data.get("grants", [])
    if "--json" in args:
        print(json.dumps({"count": len(pending), "url": f"{url}/approvals" if url else "", "grants": len(grants),
                          "oldest": pending[0] if pending else None}))
        return 0
    if not pending:
        print("No pending approvals.")
    for a in pending:
        print(f"#{a['id']:<4} {a['service']:<14} {a['part']:<7} {a['action'][:90]}")
    for g in grants:
        print(f"grant  {g['service']:<14} {g['part']:<7} until {time.strftime('%H:%M', time.localtime(g['until']))}")
    return 0


# ---------- audit log and approvals (access mode "confirm") ----------
# Every write through svc is logged; with access "confirm" it first needs the user's approval in tentacontrol (Approvals).
# Claude runs as an unprivileged user and reaches services only through svc (sudo), so the modes are enforced here.


CONTROL_INTERNAL = os.environ.get("TC_CONTROL_INTERNAL", "http://tentacontrol:8080")
AUDIT_DIR = os.path.join(core.TC_DIR, "data", "control")
AUDITED = False  # set by audit(): a call that logged itself needs no "read" entry from main()
TOKEN_FILE = os.path.join(core.TC_DIR, "data", "control", "svc-token")
APPROVAL_TIMEOUT = 600


def access_mode(part, default="read"):
    """the effective access of a part – ro/rw are understood as read/write, unknown values are read"""
    if core.job_read_only():
        return "read"  # a read-only scheduled job: every tentacle is read-only, whatever its own access
    return tclib.access(part.get("access"), default)


def audit(service, part, mode, action, decision, rc=None, duration=None, detail="", error="", excerpts=None, category=None,
          approver="", grant="", reason="", intent=None, strict=False):
    """append one line to the audit log (format: tclib.audit_entry) → the entry's id; part "claude" is one of Claude's
    own tools (tc-guard), everything else a tentacle. Never lets the command fail – except strict (the "started" entry
    of a write): then an unwritable log ends svc before anything is executed (fail closed)"""
    global AUDITED
    AUDITED = True
    category = category or ("tool" if part == "claude" else "service")
    entry = tclib.audit_entry(category, service, action, decision, part=part, mode=mode, origin=core.origin(),
                              exit=rc, seconds=None if duration is None else round(duration, 1), detail=detail, error=error,
                              excerpts=[{"reason": r, "text": x} for r, x in (excerpts or [])], approver=approver, grant=grant,
                              reason=reason, intent=intent, cid=core.CID)
    try:
        tclib.audit_write(AUDIT_DIR, entry)
    except OSError as e:
        if strict:
            report("audit", f"Not executed: audit log not writable ({service})", f"{action[:200]}\n{e}")
            sys.exit(f"svc: {service}: {action[:80]} – not executed: the audit log is not writable ({e}). "
                     "Writes only run when they can be logged – tell the user.")
        print(f"svc: audit log not writable ({e})", file=sys.stderr)
    return entry["id"]


def _control(method, path, payload=None, timeout=40):
    import urllib.request
    try:
        token = open(TOKEN_FILE).read().strip()
    except OSError:
        raise RuntimeError("no svc token from tentacontrol (data/control/svc-token) – is tentacontrol running?")
    req = urllib.request.Request(CONTROL_INTERNAL + path, method=method,
                                 data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"X-TC-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


CONTROL_GONE = 120  # seconds svc keeps waiting for an approval while tentacontrol does not answer (a restart)
HANDOFF_EXIT = 75  # EX_TEMPFAIL: the approval is still pending, run the same command again to keep waiting


def request_approval(service, part, action, interactive=False, review=None):
    """('approved'|'denied'|'expired'|'error'|'handoff', who/why/link, {approver, grant}) – waits for the user's decision
    in tentacontrol.
    A Claude session gets 'handoff' after APPROVAL_HANDOFF seconds: a running command shows nothing in the chat
    (Remote Control in the browser), so Claude posts the link and runs the same command again – tentacontrol hands the
    same request back to the same session (pending, or decided and not used yet)."""
    try:
        res = _control("POST", "/internal/approvals", {"service": service, "part": part, "action": action, "origin": core.origin(),
                                                      "cid": core.CID, **(review or {})})
        rid = res["id"]
    except Exception as e:  # noqa: BLE001
        return "error", f"tentacontrol not reachable: {e}", {}
    if res.get("status") != "pending":  # an active "Approve + 15 min" grant, or a decision made while svc was handed back
        return res["status"], res.get("by", ""), _who(res)
    base = (core.ENV.get("CONTROL_URL") or "").rstrip("/")
    where = f"{base}/approvals#a-{rid}" if base else f"tentacontrol → Approvals (#{rid})"
    handoff = 0 if interactive or core.job() or not core.origin().get("session") else tclib.approval_handoff(core.ENV)
    if res.get("again"):
        print(f"svc: ⏳ still waiting for approval #{rid} – {where}", file=sys.stderr, flush=True)
    else:
        print(f"svc: ⏳ approval needed – {where} (request #{rid}, up to {APPROVAL_TIMEOUT // 60} min): {action}",
              file=sys.stderr, flush=True)
    start = time.time()
    end = start + APPROVAL_TIMEOUT + 30
    reminded, lost = start, 0
    while time.time() < end:
        if handoff and not res.get("again") and time.time() - start >= handoff:
            return "handoff", where, {}
        if time.time() - reminded >= 60:  # visible in the live output of a running command
            reminded = time.time()
            print(f"svc: ⏳ still waiting for approval #{rid} ({int(reminded - start) // 60} min) – {where}", file=sys.stderr, flush=True)
        try:
            st = _control("GET", f"/internal/approvals/{rid}?wait={min(25, handoff) if handoff and not res.get('again') else 25}",
                          timeout=40)
            lost = 0
        except Exception as e:  # noqa: BLE001 – tentacontrol restarting: it keeps the request, keep asking for a while
            lost = lost or time.time()
            if time.time() - lost > CONTROL_GONE:
                return "error", f"tentacontrol not reachable: {e}", {}
            time.sleep(3)
            continue
        if st.get("status") != "pending":
            return st.get("status", "error"), st.get("by", ""), _who(st)
    return "expired", "", {}


def _who(res):
    """approver, grant and the reason of a denial from tentacontrol's answer, for the audit entry (only well-formed values)"""
    who = {k: str(res.get(k, ""))[:40] for k in ("approver", "grant") if re.fullmatch(r"[\w .:@()+-]{0,40}", str(res.get(k, "")))}
    reason = re.sub(r"[\x00-\x1f\x7f]+", " ", str(res.get("reason") or "")).strip()[:200]
    if reason:
        who["reason"] = reason
    return who


def report(event, title, body=""):
    """tell tentacontrol about something worth a notification – best effort, never blocks for long"""
    try:
        _control("POST", "/internal/event", {"event": event, "title": title, "body": body}, timeout=3)
    except Exception:  # noqa: BLE001
        pass


def run_teed(run, keep=4096):
    """run() with fd 2 passed through a pipe: everything still reaches the caller, the end is kept for the audit log
    (child processes inherit fd 2, so their stderr is caught as well) → (rc, captured stderr tail)"""
    import threading
    sys.stderr.flush()
    saved = os.dup(2)
    r, w = os.pipe()
    os.dup2(w, 2)
    os.close(w)
    buf = bytearray()

    def pump():
        while chunk := os.read(r, 4096):
            view = memoryview(chunk)
            while view:
                view = view[os.write(saved, view):]
            buf.extend(chunk)
            del buf[:-keep]
    t = threading.Thread(target=pump, daemon=True)
    t.start()
    try:
        rc = run()
    finally:
        sys.stderr.flush()
        os.dup2(saved, 2)  # closes the last write end of svc itself – the pump ends once the children's copies are gone
        t.join(timeout=3)  # a background process that keeps fd 2 open must not hold svc up
        if not t.is_alive():
            os.close(r)
            os.close(saved)
    return rc, buf.decode(errors="replace")


def error_tail(text, lines=2, limit=300):
    """the last lines of a failed write's stderr – secrets blanked, svc's own progress lines left out"""
    keep = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("svc: ⏳") and not ln.startswith("svc: ✓")]
    return safeguards._redact_text("\n".join(keep[-lines:]))[-limit:]


class Stop(Exception):
    """a write that must not run: the message for Claude; link set when the approval is only handed back (still pending)"""

    def __init__(self, message, link=""):
        super().__init__(message)
        self.message, self.link = message, link


def admit(service, part, mode, action, interactive=False, review=None):
    """the gate in front of one write: blocked for read, logged for write, approved first for confirm → what finish()
    needs; raises Stop when it must not run. Never exits – the MCP proxy answers a refused tool call and goes on"""
    if mode == "read":
        audit(service, part, mode, action, "blocked")
        report("blocked", f"Blocked: {service} ({part}) is read-only", action)
        raise Stop(f"svc: {service} is read-only ({part}) – '{action[:80]}' is not allowed")
    decision, by, who = "auto", "", {}
    if mode == "confirm":
        decision, by, who = request_approval(service, part, action, interactive, review)
        if decision == "handoff":
            raise Stop("approval still pending", link=by)
        if decision != "approved":
            audit(service, part, mode, action, decision, detail="" if who.get("approver") else by, **who)
            reason = who.get("reason", "")
            raise Stop(f"svc: {service}: {action[:80]} – {decision}{(' (' + by + ')') if by else ''}. "
                       "Not executed – tell the user, don't work around it."
                       + (f"\nReason given by the user: “{reason}” – if it states a lasting rule, propose it as a note "
                          "where it belongs (Learn where it belongs)." if reason else ""))
    detail = "" if who.get("approver") else by
    try:
        started = audit(service, part, mode, action, "started", detail=detail, strict=True, **who)  # no entry, no write
    except SystemExit as e:
        raise Stop(str(e.code)) from None
    return {"service": service, "part": part, "mode": mode, "action": action, "decision": decision, "by": by,
            "detail": detail, "who": who, "started": started}


def finish(ctx, rc, duration, error=""):
    """the closing audit entry of an admitted write"""
    audit(ctx["service"], ctx["part"], ctx["mode"], ctx["action"], ctx["decision"], rc=rc, duration=duration,
          detail=ctx["detail"], error=error, intent=ctx["started"], **ctx["who"])


def guarded(service, part, mode, action, run, interactive=False, review=None):
    """run() performs a write: blocked for read, logged for write, approved first for confirm
    (interactive: a terminal session – stderr stays the terminal, nothing is captured; review: diff and flags shown with
    the approval)"""
    try:
        ctx = admit(service, part, mode, action, interactive, review)
    except Stop as e:
        if e.link:
            print(f"svc: ⏸ approval still pending – the user approves it at {e.link}\n"
                  "Give the user this link in one line now, then run exactly the same command again "
                  "(Bash timeout 600000 ms): it waits for the same request.", file=sys.stderr, flush=True)
            sys.exit(HANDOFF_EXIT)
        sys.exit(e.message)
    if ctx["decision"] == "approved":
        print(f"svc: ✓ approved{' – ' + ctx['by'] if ctx['by'].startswith('grant') else ''}", file=sys.stderr, flush=True)
    t = time.time()
    rc, err = (run(), "") if interactive else run_teed(run)
    finish(ctx, rc, time.time() - t, error_tail(err) if rc else "")
    return rc


AUDIT_MAX = 50000
AUDIT_USAGE = ("usage: svc audit [n] [--since 24h|7d|30d] [--json] [search …]\n"
               "  n        newest entries to show (default 20, max 50000)\n"
               "  --json   the entries as stored (without excerpts), one JSON object per line\n"
               "  search   as on Logs → Audit: words, field:value, -field:value")


def cmd_audit(args):
    """svc audit [n] [--since 24h|7d|30d] [--json] [search …] – search as on Logs → Audit: words, field:value, -field:value"""
    n, since, terms, as_json = 20, 0, [], False
    it = iter(args)
    for a in it:
        if a.isdigit():
            n = int(a)
        elif a in ("-h", "--help"):
            print(AUDIT_USAGE)
            return 0
        elif a == "--json":
            as_json = True
        elif a == "--since":
            v = next(it, "")
            m = re.fullmatch(r"(\d+)([hd])", v)
            if not m:
                sys.exit("svc audit: --since takes e.g. 24h or 7d")
            since = time.time() - int(m.group(1)) * (3600 if m.group(2) == "h" else 86400)
        elif a in ("--category", "--service", "--decision", "--actor"):  # older options → the same terms
            terms.append(f"{a[2:]}:{next(it, '')}")
        elif a.startswith("--"):  # -field:value is a search term, --anything an option
            sys.exit(f"svc audit: unknown option {a}\n{AUDIT_USAGE}")
        else:
            terms.append(a)
    if n > AUDIT_MAX:
        print(f"svc audit: at most {AUDIT_MAX} entries – showing {AUDIT_MAX}", file=sys.stderr)
        n = AUDIT_MAX
    query = " ".join(terms)
    unknown = tclib.audit_unknown_keys(query)
    if unknown:
        print(f"svc audit: no field {', '.join(unknown)} – searched as text. Fields: {' '.join(tclib.AUDIT_SEARCH_KEYS)}",
              file=sys.stderr)
    entries, more = tclib.audit_read(AUDIT_DIR, limit=n, since=since, query=query)
    if not entries:
        if not as_json:
            print("No matching audit entries.")
        return 0
    for e in reversed(entries):
        if as_json:
            # excerpts are the flagged text itself (a possible prompt injection) – Logs → Audit shows them, svc doesn't
            print(json.dumps({k: v for k, v in e.items() if not k.startswith("_") and k != "excerpts"}, ensure_ascii=False))
            continue
        v = e.get("_view") or tclib.audit_view(e)
        extra = f" exit {e['exit']}" if "exit" in e else f" ×{e['count']}" if "count" in e else ""
        print(f"{e['ts'][:19]}  {v['actor']:<6} {v['type']:<7} {v['outcome']:<8} {v['target']:<16} {v['action'][:90]}{extra}")
        if e.get("error"):
            print(f"{'':<21}↳ {e['error'].replace(chr(10), ' · ')[:160]}")
        if e.get("reason"):
            print(f"{'':<21}↳ reason: {e['reason'][:160]}")
    if more and since:  # the window would look complete; on stderr: a pipe (| head, | grep) still gets only entries
        print(f"svc audit: only the newest {len(entries)} matching entries, from {entries[-1]['ts'][:19]} – older ones "
              "in the window are left out; raise n or narrow the search", file=sys.stderr)
    return 0
