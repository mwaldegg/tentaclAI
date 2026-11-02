"""Approvals (pending requests, grants, recent requests), svc's and the gateway's internal endpoints, and the Network page."""
import asyncio
import json
import re
import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .. import activity, auditlog, auth, dockerops, egress, notify
from ..envfile import update_env
from ..web import page, respond, templates, toast
import tclib  # noqa: E402  shared with the sandbox tools

router = APIRouter()


@router.post("/internal/approvals")
async def internal_approval_create(request: Request):
    data = await request.json()
    rid = activity.create(data.get("service", "?"), data.get("part", "?"), data.get("action", "?"), data.get("origin"),
                          activity.clean_review(data.get("diff", ""), data.get("flags"), data.get("risks")), cid=data.get("cid", ""))
    a = activity.APPROVALS[rid]
    again = a.pop("again", False)
    return JSONResponse({"id": rid, **activity.use(a), "again": again})


@router.post("/internal/event")
async def internal_event(request: Request):
    """svc reports something worth a notification (e.g. a blocked write)"""
    d = await request.json()
    if d.get("event") in ("blocked", "injection"):
        notify.emit(d["event"], str(d.get("title", ""))[:200], str(d.get("body", ""))[:500])
    return JSONResponse({"ok": True})


@router.post("/internal/egress/event")
async def internal_egress_event(request: Request):
    """the gateway reports a refused destination"""
    d = await request.json()
    target = f"{str(d.get('host', ''))[:200]}:{int(d.get('port', 0) or 0)}"
    notify.emit("blocked", f"Network: {target} {str(d.get('reason', 'refused'))[:30]}", "The sandbox tried to connect.",
                key=f"blocked:{target}", link=notify.control_link("/network"))
    return JSONResponse({"ok": True})


@router.post("/internal/egress/audit")
async def internal_egress_audit(request: Request):
    """the gateway's connections, counted per destination and window – one audit entry each"""
    d = await request.json()
    if d.get("entries"):
        await asyncio.to_thread(egress.learn_start)
    for e in (d.get("entries") or [])[:1000]:
        host, reason = str(e.get("host", ""))[:200], re.sub(r"[^a-z-]", "", str(e.get("reason", "")))[:20]
        try:
            port, count, first = int(e.get("port", 0)), int(e.get("count", 1)), int(e.get("first", 0))
        except (TypeError, ValueError):
            continue
        if not tclib.HOST_RE.fullmatch(host.strip("[]").replace(":", ".")) or not 0 < port < 65536:
            continue
        since = time.strftime("%H:%M", time.localtime(first)) if first else ""
        auditlog.write("network", f"{host}:{port}", "connect",
                       "blocked" if e.get("decision") == "blocked" else "allowed", actor="claude", count=max(1, count),
                       detail=f"{reason} · {count}× since {since}" if since else reason)
    return JSONResponse({"ok": True})


@router.get("/internal/approvals")
async def internal_approval_list():
    """pending requests and active grants – for `svc pending` (the status line in Claude's terminal)"""
    return JSONResponse({"pending": [{k: a[k] for k in ("id", "service", "part", "action", "created")} for a in activity.pending()],
                         "grants": [{k: g[k] for k in ("service", "part", "until")} for g in activity.grants()]})


@router.get("/internal/approvals/{rid}")
async def internal_approval_wait(rid: str, wait: int = 25):
    return JSONResponse(await activity.wait(rid, wait))


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request):
    """pending approvals, active grants and the latest decided requests (from the audit log)"""
    return page(request, "approvals.html")


@router.get("/activity")
async def activity_moved(request: Request):
    return RedirectResponse("/approvals", status_code=301)  # Activity is Approvals now (links in chats keep their #a-<id>)


@router.get("/partials/approvals-recent", response_class=HTMLResponse)
async def approvals_recent(request: Request):
    entries, more = await asyncio.to_thread(auditlog.approvals)
    return templates.TemplateResponse(request, "partials/approvals_recent.html",
                                      {"entries": entries, "more": more, "query": auditlog.APPROVALS_QUERY})


@router.get("/partials/approvals", response_class=HTMLResponse)
async def approvals_partial(request: Request):
    return templates.TemplateResponse(request, "partials/approvals.html",
                                      {"pending": activity.pending(), "now": time.time(),
                                       "grants": activity.grants(), "no_grant": activity.NO_GRANT_PARTS})


@router.get("/partials/approval-banner", response_class=HTMLResponse)
async def approval_banner(request: Request):
    return templates.TemplateResponse(request, "partials/approval_banner.html",
                                      {"pending": activity.pending(), "no_grant": activity.NO_GRANT_PARTS})


@router.post("/grants/revoke", response_class=HTMLResponse)
async def grant_revoke(request: Request, service: str = Form(...), part: str = Form(...)):
    activity.revoke(service, part)
    resp = await approvals_partial(request)
    resp.headers.update(toast(f"Grant for {service} ({part}) revoked"))
    return resp


@router.get("/partials/approval-count", response_class=HTMLResponse)
async def approval_count():
    n = len(activity.pending())
    # never an empty answer: app.js keeps the old content then, and the badge would stay after the last decision
    return HTMLResponse(f'<span class="nav-badge" title="{n} approval(s) waiting">{n}</span>' if n else '<span class="nav-badge" hidden></span>')


@router.get("/partials/logs-count", response_class=HTMLResponse)
async def logs_count():
    """the ⚠ badge next to Logs: possible prompt injections flagged since Logs → Audit was last opened"""
    f = auditlog.unseen_flags()
    return HTMLResponse(f'<span class="nav-badge warn" title="{f} possible prompt injection(s) flagged since the audit log was last opened">⚠ {f}</span>'
                        if f else '<span class="nav-badge" hidden></span>')


@router.get("/approvals/watch")
async def approvals_watch(seen: str = "", wait: int = 25):
    """for app.js: answers once the pending approvals differ from `seen` (or after `wait` s) – a long poll, so a hidden
    tab learns of a request within a second although the browser slows down its timers (desktop notification, title)"""
    def state():
        p = activity.pending()
        return p, activity.BOOT + ":" + ",".join(a["id"] for a in p)
    end = time.time() + max(0, min(wait, 25))
    p, sig = state()
    while sig == seen and time.time() < end:
        await asyncio.sleep(1)
        p, sig = state()
    return JSONResponse({"sig": sig, "boot": activity.BOOT,
                         "pending": [{"id": a["id"], "service": a["service"], "part": a["part"], "action": a["action"][:200],
                                      "from": a.get("from", "")} for a in p]})


@router.post("/approvals/{rid}/{verdict}", response_class=HTMLResponse)
async def approval_decide(request: Request, rid: str, verdict: str):
    if verdict not in ("approve", "approve15", "deny", "net10", "net60", "always", "block"):
        return PlainTextResponse("", status_code=400)
    who = auth.username(request) or "tentacontrol"
    a = activity.APPROVALS.get(rid) or {}
    network = ("net10", "net60", "always", "block")  # the network card's buttons; approve15 only for the others
    if a and verdict not in ("approve", "deny") and (verdict in network) != (a.get("part") == "network"):
        return PlainTextResponse("", status_code=400)
    if verdict in ("always", "block") and a.get("part") == "network" and a.get("status") == "pending":
        egress.add("allow" if verdict == "always" else "block", a["service"])  # host:port
    reason = (await request.form()).get("reason", "") if verdict == "deny" else ""
    ok = activity.decide(rid, verdict not in ("deny", "block"), who=who, grant=verdict in ("approve15", "net10", "net60"),
                         seconds={"net10": 600, "net60": 3600}.get(verdict), reason=reason)
    if ok:  # the status stays approved / denied for the gateway; the audit entry names the lasting choice
        if verdict in ("always", "block"):  # lasting: the destination is on a list now
            a["grant"] = "always" if verdict == "always" else "blocklist"
        activity.audit_network(a, {"block": "blocked", "deny": "denied"}.get(verdict, "approved"))
    resp = await (approval_banner(request) if request.query_params.get("view") == "banner" else approvals_partial(request))
    if not ok:
        resp.headers.update(toast("Request no longer pending", "warn"))
    return resp


@router.get("/internal/egress/policy")
async def internal_egress_policy():
    """for the egress gateway (inside the sandbox network) – host lists only, no secrets"""
    return JSONResponse(await asyncio.to_thread(egress.policy))


@router.post("/internal/egress/ask")
async def internal_egress_ask(request: Request):
    """the gateway asks about an unknown destination (enforce) – only creates a request, the user decides"""
    data = await request.json()
    try:
        host, port = egress.normalize(str(data.get("host", ""))), int(data.get("port", 0))
    except (ValueError, TypeError):
        return JSONResponse({"error": "bad target"}, status_code=400)
    if "*" in host or "/" in host or ":" in host and not tclib.is_ip(host) or not 0 < port < 65536:
        # one destination, as the gateway saw it – "Always" would put a pattern (*.com, 0.0.0.0/0) on the allowlist
        return JSONResponse({"error": "bad target"}, status_code=400)
    rid = activity.create(f"{host}:{port}", "network", "connect")
    a, client = activity.APPROVALS[rid], data.get("client_port")
    if isinstance(client, int) and 0 < client < 65536 and not a.get("lookup"):
        a["lookup"] = True  # once per request – further connections to the same target wait for the same decision
        task = asyncio.get_running_loop().create_task(_find_process(rid, client))  # the gateway holds the connection meanwhile
        _LOOKUPS.add(task)
        task.add_done_callback(_LOOKUPS.discard)
    return JSONResponse({"id": rid})


_LOOKUPS = set()  # running lookups – the event loop keeps only weak references to tasks


async def _find_process(rid, client_port):
    """which process of the sandbox opened the connection – asked in the sandbox as root (svc origin-of)"""
    code, out = await asyncio.to_thread(dockerops.run, ["svc", "origin-of", str(client_port)])
    try:
        found = json.loads(out.strip().splitlines()[-1]) if code == 0 and out.strip() else {}
    except (ValueError, IndexError):
        found = {}
    activity.set_process(rid, found)


@router.get("/internal/egress/wait/{rid}")
async def internal_egress_wait(rid: str, wait: int = 20):
    a = activity.APPROVALS.get(rid)
    if not a or a["part"] != "network":
        return JSONResponse({"status": "error"})
    return JSONResponse(await activity.wait(rid, wait))


@router.post("/network/rule", response_class=HTMLResponse)
async def network_rule(request: Request, kind: str = Form(...), entry: str = Form(...), op: str = Form("add")):
    if kind not in ("allow", "block"):
        return PlainTextResponse("", status_code=400)
    try:
        if op == "remove":
            egress.remove(kind, entry)
            msg = f"{entry} removed from the {kind}list"
        else:
            e = egress.add(kind, entry)
            msg = f"{e} added to the {kind}list"
            still = egress.still_blocked(e) if kind == "allow" else ""
            if still:
                return respond(request, f"{e} allowed, but the blocklist entry {still} still blocks it", "warn", refresh=True)
    except ValueError as e:
        return respond(request, f"Invalid entry: {e}", "err")
    return respond(request, msg, refresh=True)


@router.post("/network/clear", response_class=HTMLResponse)
async def network_clear(request: Request):
    egress.clear_seen()
    return respond(request, "List cleared – it fills again with new connections", refresh=True)


@router.post("/network/direct-ip", response_class=HTMLResponse)
async def network_direct_ip(request: Request):
    new = "ask" if egress.direct_ip() == "block" else "block"
    update_env({"EGRESS_DIRECT_IP": new})
    return respond(request, f"IP targets: {new} (in enforce mode, applied within 15 s)", refresh=True)


@router.post("/network/mode", response_class=HTMLResponse)
async def network_mode(request: Request):
    new = "enforce" if egress.mode() == "permissive" else "permissive"
    update_env({"EGRESS_MODE": new})  # also ends a learning phase early
    return respond(request, f"Network mode: {new} (the gateway applies it within 15 s)", refresh=True)


@router.post("/network/learned", response_class=HTMLResponse)
async def network_learned(request: Request, op: str = Form("allow")):
    if op == "dismiss":
        await asyncio.to_thread(egress.learned_dismiss)
        return respond(request, "Learned destinations dismissed – they stay on the Seen list", refresh=True)
    n, skipped = await asyncio.to_thread(egress.learned_allow)
    msg = f"{n} destination{'s' if n != 1 else ''} added to the allowlist"
    if skipped:
        return respond(request, msg + f" – not added: {'; '.join(skipped[:5])}" + (" …" if len(skipped) > 5 else ""), "warn", refresh=True)
    return respond(request, msg, refresh=True)


@router.get("/network", response_class=HTMLResponse)
async def network_page(request: Request, tab: str = "seen"):
    """egress gateway: seen destinations, allow and block lists, mode"""
    rows = await asyncio.to_thread(egress.seen_rows)
    fmt = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "–"  # noqa: E731
    for r in rows:
        r["first_s"], r["last_s"] = fmt(r.get("first")), fmt(r.get("last"))
    tent = await asyncio.to_thread(egress.tentacles)
    mode = await asyncio.to_thread(egress.mode)
    learn, learned = await asyncio.to_thread(egress.learning), await asyncio.to_thread(egress.learned)
    return page(request, "network.html", tab=tab if tab in ("seen", "allow", "block") else "seen", rows=rows, mode=mode,
                direct_ip=egress.direct_ip(), learn=learn if egress.configured() == "learn" or learn.get("ended") else {},
                learned=learned, learn_at=lambda ts: time.strftime("%H:%M", time.localtime(ts)) if ts else "",
                rules=egress.rules(), default=egress.default_list(),
                tentacles=sorted((f"{h}:{p}" if p else h, n) for (h, p), n in tent.items()),
                counts={k: sum(1 for r in rows if r["kind"] == k) for k in ("tentacle", "default", "allow", "unknown", "blocked")})
