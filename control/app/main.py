"""tentacontrol – web admin for the tentaclai sandbox + service gateway for Claude Code."""
import asyncio
import contextlib
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import tclib

from . import activity, auditlog, auth, central, connectors, dockerops, extensions, netguard, notify, scheduled, services_store, skills, updatecheck, usage
from .config import SSH_DIR
from .envfile import read_env
from .routes import backup, central as central_routes, claude, jobs, network, settings, ssh, system, tentacles
from .web import BASE, TC_VERSION, page, templates
from .log import REQUEST_ID, get, request_id

log = get("main")


@contextlib.asynccontextmanager
async def lifespan(_app):
    """startup: activity token, background loops (notifications, usage, update check, scheduled jobs), setup hint"""
    for start in (migrate, prepare_activity, start_audit, refresh_builtin_jobs, start_notifications, start_update_check,
                  start_scheduled_jobs, start_extensions, start_central, announce_setup):
        await start()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
app.mount("/vendor", StaticFiles(directory=os.environ.get("VENDOR_DIR", "/app/vendor")), name="vendor")  # VENDOR_DIR: tests

PUBLIC = ("/login", "/setup", "/static/", "/vendor/", "/healthz", "/internal/", "/favicon.ico", "/apple-touch-icon",
          "/sso/")  # /internal/: see internal_refused; /sso/: the assertion of the central server
FORWARDED = ("x-forwarded-for", "x-real-ip", "forwarded")


def internal_refused(request, path):
    """the internal endpoints: the gateway's (/internal/egress/…) never through the reverse proxy, svc's only with its
    token – on top of netguard, which decides by the source address"""
    if path.startswith("/internal/egress/"):
        return any(h in request.headers for h in FORWARDED)
    return path.startswith("/internal/") and not activity.token_ok(request.headers.get("x-tc-token", ""))


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if not netguard.allowed(path, request.client.host if request.client else ""):
        return PlainTextResponse("not from here", status_code=403)  # sandbox: svc endpoints only; gateway: egress only
    if internal_refused(request, path):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if extensions.blocked_path(path):  # an extension disabled since the start (or never loaded)
        return PlainTextResponse("Not Found", status_code=404)
    if not path.startswith(PUBLIC):
        if not auth.logged_in(request):
            if request.headers.get("hx-request"):
                return PlainTextResponse("", headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login" if auth.has_account() else "/setup", status_code=303)
        if auth.profile_missing(auth.current_user(request)) and not path.startswith(("/account/complete", "/logout")):
            if request.headers.get("hx-request"):  # an account from before usernames: username + email first
                return PlainTextResponse("", headers={"HX-Redirect": "/account/complete"})
            return RedirectResponse("/account/complete", status_code=303)
        if request.method == "POST" and not auth.same_origin(request):
            return PlainTextResponse("invalid origin", status_code=403)
        if request.method == "POST" and path.startswith("/account/") and auth.is_central(request):
            return PlainTextResponse("your account is managed by tentaclAI Enterprise", status_code=403)
        off = central.hidden_feature_of(path)
        if off:  # hidden by the central server's profile
            if request.method == "GET" and not request.headers.get("hx-request") and not path.startswith("/partials/"):
                return page(request, "feature_off.html", nav="", feature=central.FEATURES[off][0])
            return PlainTextResponse("", status_code=403)
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


AUDIT_SKIP = ("/internal/", "/login", "/setup", "/logout", "/sso/", "/approvals/", "/topology/layout", "/usage/refresh")  # logged elsewhere / layout only
AUDIT_AREA = {"ssh": "SSH hosts", "rc": "Remote Control", "container": "sandbox", "grants": "Approvals", "updates": "updates",
              "account": "account", "claude": "Claude"}


@app.middleware("http")
async def audit_admin(request: Request, call_next):
    """every change made in tentacontrol (POST/PUT/DELETE) lands in the audit log – what and on which object, never the form"""
    response = await call_next(request)
    path = request.url.path
    if (request.method in ("POST", "PUT", "PATCH", "DELETE") and not path.startswith(AUDIT_SKIP) and auth.logged_in(request)
            and not getattr(request.state, "audited", False)):  # a route that wrote its own entries
        endpoint = getattr(request.scope.get("endpoint"), "__name__", "") or path
        params = [str(v)[:80] for v in request.path_params.values()]
        area = path.strip("/").split("/")[0]
        auditlog.user(request, "admin", params[0] if params else AUDIT_AREA.get(area, area or "tentacontrol"),
                      endpoint.replace("_", " ") + (f": {' · '.join(params[1:])}" if params[1:] else ""),
                      "ok" if response.status_code < 400 else "failed", part=area[:20], mode=request.method,
                      detail=f"{request.method} {path} → {response.status_code}")
    return response


app.add_middleware(SessionMiddleware, secret_key=auth.session_secret(), session_cookie="tentacontrol",
                   max_age=12 * 3600, same_site="strict", https_only=False)


@app.middleware("http")
async def secure_cookie(request: Request, call_next):
    """mark the session cookie Secure whenever the site is reached via https (directly or through a proxy)"""
    response = await call_next(request)
    if request.url.scheme == "https":
        raw = [(k, v) for k, v in response.raw_headers]
        response.raw_headers[:] = [(k, v + b"; secure" if k == b"set-cookie" and v.startswith(b"tentacontrol=")
                                    and b"secure" not in v.lower() else v) for k, v in raw]
    return response


@app.middleware("http")
async def tag_request(request: Request, call_next):
    """outermost of the http middlewares (added last): the request id for the log lines and the audit entries of this request (cid), sent back as X-Request-ID"""
    rid = request_id(request.headers.get("x-request-id", ""))
    token = REQUEST_ID.set(rid)
    try:
        response = await call_next(request)
    finally:
        REQUEST_ID.reset(token)
    response.headers["X-Request-ID"] = rid
    return response


# around everything: the client address behind a reverse proxy is settled before any middleware reads it
app.add_middleware(netguard.ProxyHeaders)


async def migrate():
    """one-time adjustments of an existing installation"""
    if auth.migrate():
        log.info("migration: admin password → account (data/control/users.json) – set username and email at the next sign-in")
    services = services_store.migrate_access()
    hosts = tclib.ssh_migrate_access(os.path.join(SSH_DIR, "config.d"))
    if services or hosts:
        log.info(f"migration: access ro/rw → read/write in {', '.join(services + hosts)} (backups: *.bak-*-access)")
    mcp = services_store.migrate_mcp_access()
    if mcp:
        log.info(f"migration: MCP access → write (unchanged behaviour, now logged) in {', '.join(mcp)} (backups: *.bak-*-mcp)")


async def refresh_builtin_jobs():
    """built-in jobs whose task the user never changed follow the shipped one"""
    try:
        updated = await asyncio.to_thread(scheduled.refresh_builtins)
    except (ValueError, OSError) as e:
        log.warning(f"built-in jobs: {e}")
        return
    if updated:
        log.info(f"built-in jobs: task updated – {', '.join(updated)}")


async def prepare_activity():
    activity.ensure_token()
    activity.load()


async def start_audit():
    """the audit log: tentacontrol's start as an entry, archives past the retention removed every 6 h"""
    auditlog.write("system", "tentacontrol", f"started {TC_VERSION}", actor="system")
    asyncio.get_running_loop().create_task(auditlog.prune_loop())


async def discover_claude():
    """claude.ai connectors (new ones start disabled) and skills – `claude mcp list` health-checks every MCP server,
    so this runs hourly, after a sign-in and on "Check", not every few minutes"""
    await asyncio.to_thread(connectors.discover)
    await asyncio.to_thread(skills.discover)


async def start_notifications():
    loop = asyncio.get_running_loop()
    loop.create_task(notify.worker())

    async def watch():
        """state changes worth a notification – reported once per change, not every minute"""
        state, down_since = {}, None
        await asyncio.sleep(60)
        while True:
            try:
                st = await asyncio.to_thread(dockerops.status)
                gw = await asyncio.to_thread(dockerops.container_running, "tentaclai-egress")
                for name, up in (("tentaclai", st.get("running")), ("tentaclai-egress", gw)):
                    if state.get(name, True) and not up:
                        notify.emit("container", f"{name} is not running", "Start it in tentacontrol → Overview.",
                                    key=f"container:{name}", link=notify.control_link("/"))
                    state[name] = up
                if st.get("running"):
                    logged = await asyncio.to_thread(dockerops.logged_in_claude)
                    if state.get("logged", True) and not logged:
                        notify.emit("logged_out", "Claude is signed out", "Sign in again: Overview → Sign in now.",
                                    key="logged_out", link=notify.control_link("/"))
                    if state.get("logged") is False and logged:
                        loop.create_task(discover_claude())  # a new sign-in can bring other connectors and skills
                    state["logged"] = logged
                    rc = await asyncio.to_thread(dockerops.rc_info)
                    enabled = (read_env().get("RC_ENABLED", "true") or "true").lower() == "true"
                    ok = (rc or {}).get("state") == "connected" or not enabled
                    down_since = None if ok else (down_since or time.time())
                    is_down = down_since is not None and time.time() - down_since > 180
                    if is_down and not state.get("rc_down"):
                        notify.emit("rc_down", "Remote Control is down", f"State: {(rc or {}).get('state', 'no session')}",
                                    key="rc_down", link=notify.control_link("/"))
                    state["rc_down"] = is_down
                up = updatecheck.status(TC_VERSION)
                if up.get("available") and state.get("update") != up.get("latest"):
                    notify.emit("update", f"tentaclAI {up['latest']} is available", up.get("url", ""), key=f"update:{up['latest']}")
                    state["update"] = up.get("latest")
            except Exception as e:  # noqa: BLE001
                log.warning(f"notify watch: {e}")
            await asyncio.sleep(60)
    loop.create_task(watch())

    async def usage_loop():
        """plan limits every 10 min (no model call), local token totals every 5 min, connectors and skills hourly;
        quota notification at 80 % and 100 %, once per window"""
        n = 0
        await asyncio.sleep(20)
        while True:
            try:
                await asyncio.to_thread(usage.refresh_local)
                if n % 12 == 0 and dockerops.status().get("running"):
                    await discover_claude()  # hourly
                if n % 2 == 0 and dockerops.status().get("running") and await asyncio.to_thread(dockerops.logged_in_claude):
                    p = await asyncio.to_thread(usage.refresh_plan)
                    for lim in usage.check_quota(p.get("limits", [])):
                        name = "session" if lim["window"] == "session" else f"week ({lim['scope'] or 'all models'})"
                        notify.emit("quota", f"Claude {name}: {lim['percent']} % used", f"Resets {lim['resets']}.",
                                    key=f"quota:{lim['window']}:{lim['scope']}:{lim['percent'] >= 100}", link=notify.control_link("/usage"))
            except Exception as e:  # noqa: BLE001
                log.warning(f"usage: {e}")
            n += 1
            await asyncio.sleep(300)
    loop.create_task(usage_loop())


async def start_scheduled_jobs():
    loop = asyncio.get_running_loop()
    loop.create_task(scheduled.worker())
    loop.create_task(scheduled.scheduler())


async def start_update_check():
    async def loop():
        while True:  # refresh() itself only asks GitHub when the cached answer is older than 6 h
            await asyncio.to_thread(updatecheck.refresh)
            await asyncio.sleep(1800)
    asyncio.get_running_loop().create_task(loop())


async def start_central():
    """central management: the agent's sync with its server (quiet while not enrolled)"""
    asyncio.get_running_loop().create_task(central.loop())


async def start_extensions():
    """the extensions' background tasks and – when one registered on_audit – the audit log follower"""
    loop = asyncio.get_running_loop()

    def run_task(t):
        async def task():
            await asyncio.sleep(t["delay"])
            while True:
                if extensions.active(t["ext"]):
                    try:
                        if asyncio.iscoroutinefunction(t["fn"]):
                            await t["fn"]()
                        else:
                            await asyncio.to_thread(t["fn"])
                    except Exception as e:  # noqa: BLE001
                        log.warning(f"extension {t['ext']}: task {getattr(t['fn'], '__name__', '?')}: {e}")
                await asyncio.sleep(t["every"])
        return task()
    for t in extensions.tasks():
        loop.create_task(run_task(t))
    if extensions.audit_hooks():
        loop.create_task(auditlog.follow_loop(extensions.audit_hooks))


async def announce_setup():
    if not auth.has_account():
        print("=" * 72, flush=True)
        print("tentacontrol: no account yet. One-time setup link:", flush=True)
        print(f"  https://<host>/setup?token={auth.SETUP_TOKEN}", flush=True)
        print("=" * 72, flush=True)


extensions.load(app, templates)  # first: an extension's pages replace tentacontrol's own (e.g. Settings → License)
for _r in (system, backup, tentacles, ssh, network, settings, claude, jobs, central_routes):  # one router per area of the UI
    app.include_router(_r.router)
