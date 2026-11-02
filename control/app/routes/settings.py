"""Settings and its tabs: notifications, skills, models, security (two-factor sign-in), license – plus usage."""
import asyncio
import time

import segno
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth, connectors, instance, models, notify, services_store, skills, totp, usage
from ..config import RC_VARS, RESTART_VARS, SETTINGS_GROUPS, managed_elsewhere
from ..envfile import read_env, update_env
from ..config import site
from ..web import mark_restart, not_applied, page, respond, sync_services
import tclib  # noqa: E402  shared with the sandbox tools

router = APIRouter()


@router.get("/usage", response_class=HTMLResponse)
async def usage_page(request: Request, days: int = 14):
    days = 30 if days >= 30 else 14
    s = await asyncio.to_thread(usage.summary, days)
    peak = max([d["input"] + d["output"] + d["cache_read"] + d["cache_write"] for d in s["series"]] + [1])
    return page(request, "usage.html", plan=usage.plan(), s=s, days=days, peak=peak,
                fmt=lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "–",
                tok=lambda n: f"{n/1e6:.1f} M" if n >= 1e6 else (f"{n/1e3:.0f} k" if n >= 1e3 else str(n)))


@router.post("/usage/refresh", response_class=HTMLResponse)
async def usage_refresh(request: Request):
    await asyncio.to_thread(usage.refresh_local)
    p = await asyncio.to_thread(usage.refresh_plan)
    return respond(request, "Usage updated" if p.get("limits") else "Claude Code did not report limits – see the raw output",
                   "ok" if p.get("limits") else "warn", refresh=True)


@router.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    c = notify.load()
    return page(request, "notifications.html", cfg=c, events=notify.EVENTS, recent=notify.RECENT[:15],
                urls={ch["id"]: bool(notify.channel_url(ch["id"])) for ch in c["channels"]},
                parts={ch["id"]: notify.public_parts(ch["id"]) for ch in c["channels"]},
                fmt=lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)))


@router.post("/notifications/channel", response_class=HTMLResponse)
async def notifications_add(request: Request):
    f = dict(await request.form())
    try:
        cid = notify.add_channel(f.get("kind", "ntfy"), (f.get("name") or "").strip(), f)
    except ValueError as e:
        return respond(request, f"Not added: {e}", "err")
    return respond(request, f"Channel {cid} added – send a test", refresh=True)


@router.post("/notifications/channel/{cid}/test", response_class=HTMLResponse)
async def notifications_test(request: Request, cid: str):
    ok, err = await asyncio.to_thread(notify.send_now, cid, "tentaclAI test", "Notifications work. 🐙")
    return respond(request, f"Test sent to {cid}" if ok else f"Test to {cid} failed: {err}", "ok" if ok else "err")


@router.post("/notifications/channel/{cid}/edit", response_class=HTMLResponse)
async def notifications_edit(request: Request, cid: str):
    f = dict(await request.form())
    try:
        notify.update_channel(cid, f.get("name", ""), f.get("enabled"), f)
    except ValueError as e:
        return respond(request, f"Not saved: {e}", "err")
    return respond(request, f"Channel {cid} saved", refresh=True)


@router.post("/notifications/channel/{cid}/remove", response_class=HTMLResponse)
async def notifications_remove(request: Request, cid: str):
    notify.remove_channel(cid)
    return respond(request, f"Channel {cid} removed", refresh=True)


@router.post("/notifications/routes", response_class=HTMLResponse)
async def notifications_routes(request: Request):
    form = await request.form()
    routes = {ev: form.getlist(f"r_{ev}") for ev in notify.EVENTS}
    quiet = {"enabled": bool(form.get("quiet")), "from": form.get("q_from") or "23:00", "to": form.get("q_to") or "07:00"}
    notify.set_routes(routes, quiet, form.get("dedupe") or 10)
    return respond(request, "Notification settings saved")


@router.get("/skills", response_class=HTMLResponse)
async def skills_page(request: Request):
    rows = skills.listing()
    saved = sum(r.get("tokens") or 0 for r in rows if r["mode"] != "on")
    return page(request, "skills.html", rows=rows, saved=saved, modes=tclib.SKILL_MODES)


@router.post("/skills/mode", response_class=HTMLResponse)
async def skills_mode(request: Request, name: str = Form(...), mode: str = Form(...)):
    try:
        ok = await asyncio.to_thread(skills.set_mode, name, mode)
    except ValueError as e:
        return respond(request, f"Not saved: {e}", "err")
    return respond(request, f"{name}: {mode} – applies to new Claude sessions" if ok else not_applied(),
                   "ok" if ok else "warn", refresh=True)


@router.post("/skills/site/{name}/remove", response_class=HTMLResponse)
async def skills_site_remove(request: Request, name: str):
    try:
        await asyncio.to_thread(skills.remove_site, name)
    except (ValueError, OSError) as e:
        return respond(request, f"Not removed: {e}", "err")
    code, _ = await sync_services()
    return respond(request, f"Site skill {name} removed (kept as local/skills/{name}.bak-…)" if code == 0 else
                   f"Site skill {name} removed – Claude's copy goes with the next svc sync", "ok" if code == 0 else "warn", refresh=True)


@router.post("/skills/discover", response_class=HTMLResponse)
async def skills_discover(request: Request):
    ok = await asyncio.to_thread(skills.discover)
    return respond(request, "Skills checked" if ok else "Could not ask Claude Code (signed in?)", "ok" if ok else "warn", refresh=True)


@router.get("/models", response_class=HTMLResponse)
async def models_page(request: Request):
    return page(request, "models.html", m=models.current(), tasks=models.TASKS, defaults=tclib.MODELS_DEFAULT,
                aliases=tclib.MODEL_ALIASES, efforts=tclib.EFFORTS, usage_models=usage.summary()["models"])


@router.post("/models", response_class=HTMLResponse)
async def models_save(request: Request):
    try:
        ok = await asyncio.to_thread(models.set_values, dict(await request.form()))
    except ValueError as e:
        return respond(request, f"Not saved: {e}", "err")
    return respond(request, "Models saved – apply to new Claude sessions" if ok else not_applied(),
                   "ok" if ok else "warn", refresh=True)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    env = read_env()
    known = {k for _, items in SETTINGS_GROUPS for k, *_ in items}
    service_vars = {v["name"] for s in services_store.load_all() for v in s["vars"]}
    rest = sorted(k for k in env if k not in known and k not in service_vars)
    other = [k for k in rest if not managed_elsewhere(k)]
    elsewhere = {}  # where -> (link, keys)
    for k in rest:
        if m := managed_elsewhere(k):
            elsewhere.setdefault(m[0], (m[1], []))[1].append(k)
    from .. import scheduled
    # shown greyed out in empty fields whose default lives in code
    placeholders = {"JOB_READONLY_HELPERS": "default: " + ", ".join(scheduled.HELPERS_DEFAULT)}
    return page(request, "settings.html", groups=SETTINGS_GROUPS, env=env, other=other, elsewhere=elsewhere,
                placeholders=placeholders,
                is_secret=services_store.secret_check())


READONLY = {k for _, items in SETTINGS_GROUPS for k, _, _, kind in items if kind == "readonly"}


@router.post("/settings")
async def settings_save(request: Request):
    form = await request.form()
    env = read_env()
    is_secret = services_store.secret_check()
    changes = {}
    for key, value in form.items():
        if not key.startswith("k_"):
            continue
        k = key[2:]
        if k in READONLY:
            continue
        if form.get(f"remove_{k}") and k in env:
            changes[k] = None
            continue
        value = value.strip()
        if is_secret(k):
            if form.get(f"clear_{k}"):
                changes[k] = ""
            elif value:
                changes[k] = value
        elif env.get(k, "") != value:
            changes[k] = value
    new_key, new_val = form.get("new_key", "").strip(), form.get("new_val", "").strip()
    if new_key:
        if not new_key.replace("_", "").isalnum() or not new_key[0].isalpha():
            return respond(request, "invalid variable name", "err")
        changes[new_key.upper()] = new_val
    if not changes:
        return respond(request, "No changes", "info")
    if "JOB_READONLY_HELPERS" in changes:
        from .. import scheduled
        _, bad = scheduled.check_helpers(changes["JOB_READONLY_HELPERS"])
        if bad:
            return respond(request, f"Helpers refused (they could get around read-only): {', '.join(bad)}", "err")
    try:
        update_env(changes)
    except ValueError as e:
        return respond(request, str(e), "err")
    removed = sum(v is None for v in changes.values())
    msg = f"{len(changes) - removed} setting(s) saved" if removed < len(changes) else ""
    if removed:
        msg = (msg + ", " if msg else "") + f"{removed} removed"
    if "INJECTION_GUARD" in changes and not await asyncio.to_thread(connectors.apply):  # the hook in the managed settings
        msg += " – the sandbox gets the hook setting on its next start"
    if RESTART_VARS & set(changes):
        mark_restart(env, changes)
    elif RC_VARS & set(changes):
        msg += " – restart remote control on the overview to apply"
    return respond(request, msg, refresh=True)


# ---------------------------------------------------------------- Settings → Account: the account, two-factor sign-in (TOTP)

def _security(request, codes=None, error=None, status=200, done=None):
    st = auth.twofactor_status()
    secret = auth.pending_secret() if not st["enabled"] else ""
    qr = ""
    if secret:
        link = totp.uri(secret, site().get("hostname") or "tentacontrol")
        qr = segno.make(link, error="m").svg_inline(scale=4, border=2, dark="#111", light="#fff", omitsize=True)
    resp = page(request, "account.html", st=st, secret=secret, qr=qr, codes=codes, error=error, done=done, days=auth.TRUST_DAYS,
                account=auth.current_user(request) or {}, pw_min=auth.PASSWORD_MIN,
                fmt=lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "–")
    resp.status_code = status
    return resp


@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    if auth.is_central(request):  # a user of the central server: no local account, password or second factor here
        return page(request, "account_central.html", nav="account", account=auth.current_user(request) or {})
    return _security(request)


@router.get("/security")
async def security_moved():
    return RedirectResponse("/account", status_code=301)  # Settings → Security is Settings → Account now


@router.post("/account/profile", response_class=HTMLResponse)
async def security_account(request: Request, username: str = Form(""), email: str = Form(""), name: str = Form(""),
                           current: str = Form("")):
    """username, email, name – confirmed with the password"""
    u = auth.current_user(request)
    error = auth.profile_error(username, email, name, uid=u["id"])
    if not error and not await asyncio.to_thread(auth.check_password, current, u["id"]):
        await asyncio.sleep(auth.FAIL_DELAY)
        error = "the current password is wrong"
    if error:
        return _security(request, error=error, status=400)
    auth.update_profile(u["id"], username, email, name)
    return _security(request, done="Account saved.")


@router.post("/account/password", response_class=HTMLResponse)
async def security_password(request: Request, current: str = Form(""), password: str = Form(""), password2: str = Form("")):
    """a new password – browsers trusted for two-factor sign-in are revoked, as with ./tentaclai.sh passwd"""
    u = auth.current_user(request)
    error = auth.password_error(password, password2)
    if not error and not await asyncio.to_thread(auth.check_password, current, u["id"]):
        await asyncio.sleep(auth.FAIL_DELAY)
        error = "the current password is wrong"
    if error:
        return _security(request, error=error, status=400)
    request.session["gen"] = await asyncio.to_thread(auth.set_password, password, u["id"])  # this browser stays signed in
    auth.revoke_trust()
    return _security(request, done="Password changed – other browsers are signed out, browsers trusted for two-factor sign-in were revoked.")


@router.post("/account/2fa/setup", response_class=HTMLResponse)
async def security_setup(request: Request):
    if auth.twofactor_enabled():
        return RedirectResponse("/account", status_code=303)
    auth.start_setup()
    return RedirectResponse("/account", status_code=303)


@router.post("/account/2fa/confirm", response_class=HTMLResponse)
async def security_confirm(request: Request, code: str = Form("")):
    codes = await asyncio.to_thread(auth.confirm_setup, code)
    if codes is None:
        return _security(request, error="That code doesn't match – check the time on the phone and try the next one.", status=400)
    return _security(request, codes=codes)  # shown once – only the hashes are stored


@router.post("/account/2fa/recovery", response_class=HTMLResponse)
async def security_recovery(request: Request, code: str = Form("")):
    if await asyncio.to_thread(auth.check_second_factor, code) != "totp":
        return _security(request, error="Enter a current code from the app to make new recovery codes.", status=400)
    return _security(request, codes=await asyncio.to_thread(auth.new_recovery_codes))


@router.post("/account/revoke", response_class=HTMLResponse)
async def security_revoke(request: Request, tid: str = Form("")):
    auth.revoke_trust(tid or None)
    return RedirectResponse("/account", status_code=303)


@router.post("/account/2fa/disable", response_class=HTMLResponse)
async def security_disable(request: Request, password: str = Form(""), code: str = Form("")):
    ok = await asyncio.to_thread(auth.check_password, password, (auth.current_user(request) or {}).get("id")) and await asyncio.to_thread(auth.check_second_factor, code)
    if not ok:
        await asyncio.sleep(auth.FAIL_DELAY)
        return _security(request, error="Password and a current code (or a recovery code) are needed to switch it off.", status=400)
    auth.disable_twofactor()
    return RedirectResponse("/account", status_code=303)



@router.get("/license", response_class=HTMLResponse)
async def license_page(request: Request):
    """the edition and the installation ID – an extension that provides a license replaces this page"""
    iid, source = instance.instance_id()
    return page(request, "license.html", instance=iid, instance_source=source)
