"""Jobs: Claude tasks on a schedule (scheduled.py) – list with results, editor, run now, pause, cancel.
The build/update jobs of tentacontrol itself are something else: routes/system.py, /builds/<id>."""
import asyncio
import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import tclib

from .. import auditlog, extensions, knowledge, scheduled
from ..web import TC_VERSION, page, respond, sync_services, templates

router = APIRouter()
templates.env.globals.update(prompt_diff=scheduled.prompt_diff, words=scheduled.words, md=scheduled.md)  # a prompt suggestion as a diff


def _job_page(request, jid=None, job=None):
    if job is None and jid:
        job = scheduled.get(jid)
    known = scheduled.tentacles()
    warnings = scheduled.check_mentions(job, known)[1] if job and job.get("prompt") else []
    return page(request, "job_edit.html", jid=jid, job=job or {}, profiles=scheduled.PROFILES,
                notify_rules=scheduled.NOTIFY, days=scheduled.DAYS, templates=scheduled.templates(),
                rw=[x for x in scheduled.rw_tentacles()
                    if not (job or {}).get("scope") or x.removeprefix("ssh ") in scheduled.named(job.get("prompt"), known)],
                allowed=scheduled.named((job or {}).get("prompt"), known) if (job or {}).get("scope") else None,
                efforts=tclib.EFFORTS, warnings=warnings, groups=scheduled.groups(), fmt=lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)),
                tentacle_list=[{"name": n, "kind": t["kind"], "parts": ", ".join(t["parts"]), "on": t["enabled"]}
                               for n, t in sorted(known.items())])


# ---------------------------------------------------------------- svc config put job (svc token, checked by main.guard; svc asks for the approval)

async def _put_args(request):
    d = await request.json()
    return str(d.get("name", "")), d.get("definition")


@router.post("/internal/jobs/check")
async def internal_jobs_check(request: Request):
    args = await _put_args(request)
    errors, warnings, summary = scheduled.put_preview(*args)
    return JSONResponse({"errors": errors, "warnings": warnings, "summary": summary})


@router.post("/internal/jobs/put")
async def internal_jobs_put(request: Request):
    args = await _put_args(request)
    try:
        jid = await asyncio.to_thread(scheduled.put, *args)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse({"id": jid, "enabled": scheduled.get(jid).get("enabled", False)})


@router.get("/claude/jobs")
async def jobs_moved():
    return RedirectResponse("/jobs", status_code=301)  # links in older notifications


@router.get("/partials/job-count", response_class=HTMLResponse)
async def job_count():
    p = scheduled.pending_proposals()
    if p:  # a decision waits – pulsing like approvals
        return HTMLResponse(f'<span class="nav-badge" title="{p} proposal(s) to pick">{p}</span>')
    n = scheduled.unseen()
    return HTMLResponse(f'<span class="nav-badge warn" title="{n} finding(s) not looked at">{n}</span>' if n else '<span class="nav-badge" hidden></span>')


@router.get("/partials/jobs-state", response_class=HTMLResponse)
async def jobs_state(v: str = ""):
    """the Jobs page polls this: a different state (a run started, finished, failed) reloads the page"""
    if v and v != scheduled.state_token():
        return HTMLResponse("", headers={"HX-Refresh": "true"})
    return HTMLResponse("")


@router.get("/jobs", response_class=HTMLResponse)
async def jobs_page(request: Request, tab: str | None = None):
    new = scheduled.mark_seen()
    names = {jid: j.get("name", jid) for jid, j in scheduled.load().items()}
    rows = scheduled.overview()
    tabs = scheduled.tabs(rows)
    if tab is None:  # the tab picked last time
        tab = request.session.get("jobs_tab", "*")
    if tab != "*" and tab not in [t[0] for t in tabs]:
        tab = "*"  # all jobs – also when the group is gone (its last job moved away)
    request.session["jobs_tab"] = tab
    shown = rows if tab == "*" or not tabs else [r for r in rows if (r.get("group") or "") == tab]
    return page(request, "jobs.html", rows=shown, all_rows=rows, tabs=tabs, tab=tab, groups=scheduled.groups(), job_names=names,
                new=[dict(r, job_name=names.get(r.get("job"), r.get("name", "?"))) for r in new],
                new_ids={r["id"] for r in new}, templates=scheduled.templates(), token=scheduled.state_token(), now=time.time(),
                issue_url=lambda x, r=None: knowledge.issue_url(x, TC_VERSION, run=r, edition=extensions.edition()),
                fmt=lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "–")


@router.post("/jobs/seen")
async def jobs_seen(request: Request):
    scheduled.dismiss_new()
    return respond(request, "Marked as seen", refresh=True)


@router.get("/jobs/new", response_class=HTMLResponse)
async def job_new(request: Request, template: int = -1, group: str = ""):
    presets = scheduled.templates()
    job = dict(presets[template]) if 0 <= template < len(presets) else {}
    return _job_page(request, job=dict({"profile": "read-only", "notify": "findings", "max_minutes": 20, "group": group,
                                        "schedule": {"kind": "daily", "time": "07:00"}}, **job))


@router.get("/jobs/{jid}", response_class=HTMLResponse)
async def job_edit(request: Request, jid: str):
    if scheduled.get(jid) is None:
        return RedirectResponse("/jobs", status_code=303)
    return _job_page(request, jid=jid)


@router.post("/jobs/save", response_class=HTMLResponse)
async def job_save(request: Request):
    form = dict(await request.form())
    jid = form.get("jid") or None
    try:
        jid = await asyncio.to_thread(scheduled.save, form, jid)
    except (ValueError, KeyError) as e:
        return respond(request, f"Not saved: {e}", "err")
    warnings = scheduled.check_mentions(scheduled.get(jid))[1]
    if warnings:
        return respond(request, "Job saved – note: " + "; ".join(warnings), "warn", redirect=f"/jobs/{jid}")
    return respond(request, "Job saved", redirect="/jobs")


@router.post("/jobs/{jid}/run", response_class=HTMLResponse)
async def job_run(request: Request, jid: str):
    try:
        scheduled.run_now(jid)
    except ValueError as e:
        return respond(request, f"Not started: {e}", "err")
    return respond(request, "Job started – the result shows up here", refresh=True)


@router.post("/jobs/{jid}/group", response_class=HTMLResponse)
async def job_group(request: Request, jid: str):
    try:
        g = scheduled.set_group(jid, (await request.form()).get("group", ""))
    except ValueError as e:
        return respond(request, f"Not moved: {e}", "err", refresh=True)  # the select shows the old group again
    return respond(request, f"Moved to the group {g}" if g else "Moved out of its group", refresh=True)


@router.post("/jobs/{jid}/move", response_class=HTMLResponse)
async def job_move(request: Request, jid: str, step: int = 1):
    try:
        scheduled.move(jid, -1 if step < 0 else 1)
    except ValueError as e:
        return respond(request, f"Not moved: {e}", "err")
    return respond(request, "Order changed", refresh=True)


@router.post("/jobs/run-group", response_class=HTMLResponse)
async def jobs_run_group(request: Request):
    group = str((await request.form()).get("group", ""))
    try:
        ids = scheduled.run_group(group)
    except ValueError as e:
        return respond(request, f"Not started: {e}", "err")
    return respond(request, f"{len(ids)} job{'s' if len(ids) != 1 else ''} of {group} queued – each starts when the one before has finished",
                   refresh=True)


@router.post("/jobs/{jid}/toggle", response_class=HTMLResponse)
async def job_toggle(request: Request, jid: str):
    job = scheduled.get(jid)
    if job is None:
        return respond(request, "unknown job", "err")
    scheduled.set_enabled(jid, not job.get("enabled", True))
    return respond(request, f"{job['name']} {'paused' if job.get('enabled', True) else 'on'}", refresh=True)


@router.post("/jobs/{jid}/reset", response_class=HTMLResponse)
async def job_reset(request: Request, jid: str):
    """a built-in job back to its shipped definition"""
    try:
        await asyncio.to_thread(scheduled.reset_builtin, jid)
    except ValueError as e:
        return respond(request, str(e), "err")
    return respond(request, "Reset to the built-in definition", redirect=f"/jobs/{jid}")


@router.post("/jobs/{jid}/clone", response_class=HTMLResponse)
async def job_clone(request: Request, jid: str):
    try:
        new = scheduled.clone(jid)
    except ValueError as e:
        return respond(request, str(e), "err")
    return respond(request, "Copy created (paused) – adjust it and resume", redirect=f"/jobs/{new}")


@router.post("/jobs/{jid}/delete", response_class=HTMLResponse)
async def job_delete(request: Request, jid: str):
    try:
        scheduled.delete(jid)
    except ValueError as e:
        return respond(request, str(e), "err")
    return respond(request, "Job deleted", redirect="/jobs")


@router.post("/jobs/runs/{rid}/actions", response_class=HTMLResponse)
async def run_actions(request: Request, rid: str):
    picks = (await request.form()).getlist("pick")
    try:
        n = await asyncio.to_thread(scheduled.run_actions, rid, picks)
    except ValueError as e:
        return respond(request, f"Not run: {e}", "err")
    return respond(request, f"{n} proposal{'s' if n != 1 else ''} running – confirm tentacles ask for approval as usual", refresh=True)


@router.post("/jobs/runs/{rid}/discard", response_class=HTMLResponse)
async def run_discard(request: Request, rid: str, all: int = 0):
    picks = None if all else (await request.form()).getlist("pick")
    try:
        n = await asyncio.to_thread(scheduled.discard_actions, rid, picks)
    except ValueError as e:
        return respond(request, f"Not discarded: {e}", "err")
    return respond(request, f"{n} proposal{'s' if n != 1 else ''} discarded", refresh=True)


@router.post("/jobs/runs/{rid}/knowledge", response_class=HTMLResponse)
async def run_knowledge(request: Request, rid: str, discard: int = 0, reported: int = 0):
    """apply (or discard) what a run learned – each applied change gets its own audit entry; findings about tentaclAI
    are only marked (reported or dismissed)"""
    picks = (await request.form()).getlist("pick")
    try:
        if discard or reported:
            n = await asyncio.to_thread(scheduled.discard_knowledge, rid, picks, "reported" if reported else "discarded")
            return respond(request, f"{n} {'marked as reported' if reported else 'discarded'}", refresh=True)
        done = await asyncio.to_thread(scheduled.apply_knowledge, rid, picks)
    except ValueError as e:
        return respond(request, f"Not applied: {e}", "err")
    for x, err in done:
        target = "site rules" if x["target"] == "site" else f"{x['target']} {x['name']}"
        auditlog.user(request, "admin", target, f"note {x['op']} (learned in job run {rid})", "failed" if err else "ok",
                      part="knowledge", mode="POST", detail=(err or x.get("new") or x.get("old") or "")[:300])
    request.state.audited = True  # the entries above say more than the middleware's
    ok = sum(1 for _, err in done if not err)
    if ok:
        await sync_services()  # catalog and instructions show the notes
    failed = [err for _, err in done if err]
    return respond(request, f"{ok} applied" + (f", {len(failed)} not: {failed[0]}" if failed else ""),
                   "warn" if failed else "ok", refresh=True)


@router.post("/jobs/runs/{rid}/prompt", response_class=HTMLResponse)
async def run_prompt(request: Request, rid: str, use: int = 1):
    """take a run's suggested prompt for its job – or discard it"""
    try:
        jid = await asyncio.to_thread(scheduled.use_prompt, rid, bool(use))
    except ValueError as e:
        return respond(request, f"Not changed: {e}", "err")
    return respond(request, f"Prompt of {jid} updated – the earlier one can be restored in the editor" if use else "Suggestion discarded",
                   refresh=True)


@router.get("/jobs/runs/{rid}/log", response_class=HTMLResponse)
async def run_log(request: Request, rid: str):
    run = next((r for r in scheduled.history() if r.get("id") == rid), None)
    return templates.TemplateResponse(request, "partials/job_log.html", {
        "log": scheduled.read_log(rid), "running": bool(run and run.get("status") in ("queued", "running"))})


@router.post("/jobs/runs/{rid}/cancel", response_class=HTMLResponse)
async def run_cancel(request: Request, rid: str):
    try:
        await asyncio.to_thread(scheduled.cancel, rid)
    except ValueError as e:
        return respond(request, f"Not canceled: {e}", "err")
    return respond(request, "Run canceled", refresh=True)
