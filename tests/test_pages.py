"""Every tentacontrol page renders (status 200, no template error) with the dummy stack – sandbox stopped and running."""
import pytest

# every GET route without parameters is a page to render – new pages are covered without touching this file
NOT_PAGES = ("/login", "/sso/", "/setup", "/account/complete", "/security", "/activity", "/logout", "/healthz", "/api/", "/internal/", "/logs/stream", "/builds/", "/static", "/vendor",
             "/topology/ssh-status", "/claude/jobs")  # (ssh-status runs real SSH checks)
# pages with parameters or variants, rendered with the dummy stack's objects
VARIANTS = ["/services/demoapi", "/services/demodb", "/services/demohost", "/services/demogit", "/services/demomail", "/systems/box", "/ssh/box/edit",
            "/ssh/box/remove", "/network?tab=allow", "/network?tab=block"]


def pages():
    import sys
    from starlette.routing import Route
    sys.modules.get("app.main") or __import__("conftest")  # the dummy stack exists before the app is imported
    from app import main
    def walk(routes):  # included routers are wrappers around the APIRouter's own routes
        for r in routes:
            inner = getattr(r, "original_router", None)
            yield from walk(inner.routes) if inner is not None else [r]
    plain = [r.path for r in walk(main.app.routes) if isinstance(r, Route) and "GET" in (r.methods or ()) and "{" not in r.path
             and not r.path.startswith(NOT_PAGES)]
    return sorted(set(plain)) + VARIANTS


@pytest.mark.parametrize("path", pages())
def test_page_renders(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 200, f"{path}: {r.status_code} {r.text[:300]}"
    if "<html" in r.text:  # full page (dialogs and partials are fragments)
        assert "</html>" in r.text


def test_page_discovery_finds_the_known_pages():
    found = set(pages())
    assert {"/", "/services", "/settings", "/skills", "/models", "/usage", "/partials/overview", "/topology.json",
            "/claude/instructions", "/claude/memory", "/claude/settings"} <= found


def test_login_required(app_module):
    from fastapi.testclient import TestClient
    r = TestClient(app_module.app).get("/skills", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] in ("/login", "/setup")


def test_skills_mode_post(client):
    r = client.post("/skills/mode", data={"name": "dataviz", "mode": "bogus"}, headers={"HX-Request": "true"})
    assert "Not saved" in r.headers.get("HX-Trigger", "")


def test_models_post_refuses_bad_values(client):
    r = client.post("/models", data={"main": "custom", "main_custom": "x y"}, headers={"HX-Request": "true"})
    assert "Not saved" in r.headers.get("HX-Trigger", "")


def test_lifespan_runs_every_startup_hook(app_module, monkeypatch):
    from fastapi.testclient import TestClient
    ran = []
    for name in ("migrate", "prepare_activity", "start_notifications", "start_update_check", "announce_setup"):
        async def hook(name=name):
            ran.append(name)
        monkeypatch.setattr(app_module, name, hook)
    with TestClient(app_module.app):
        pass
    assert ran == ["migrate", "prepare_activity", "start_notifications", "start_update_check", "announce_setup"]


def test_skills_page_offers_no_off_for_required(client):
    import re
    html = client.get("/skills").text
    assert "required by tentaclAI" in html
    row = re.search(r'aria-label="Mode of inventory".*?</select>', html, re.S).group(0)
    assert 'value="off"' not in row and 'value="user-invocable-only"' in row


def test_site_skill_listed_shown_and_removed(client, monkeypatch):
    import os
    from app import skills
    from app.config import STACK_DIR
    d = os.path.join(STACK_DIR, "local", "skills", "renew-cert")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w") as f:
        f.write("---\nname: renew-cert\ndescription: Renew the wildcard certificate\n---\n\n1. <check> the expiry\n")
    html = client.get("/skills").text
    assert "site skill" in html and "Renew the wildcard certificate" in html and "&lt;check&gt; the expiry" in html
    assert client.post("/skills/mode", data={"name": "renew-cert", "mode": "user-invocable-only"}, headers={"HX-Request": "true"}).status_code == 200
    assert skills.load()["modes"]["renew-cert"] == "user-invocable-only"
    ran = []

    async def fake_sync():
        ran.append(1)
        return 0, ""
    monkeypatch.setattr("app.routes.settings.sync_services", fake_sync)
    client.post("/skills/site/renew-cert/remove", headers={"HX-Request": "true"})
    assert ran and not os.path.exists(d) and any(n.startswith("renew-cert.bak-") for n in os.listdir(os.path.dirname(d)))
    assert "site skill" not in client.get("/skills").text
    r = client.post("/skills/site/nope/remove", headers={"HX-Request": "true"})
    assert "Not removed" in r.headers.get("HX-Trigger", "")


def test_service_shows_mcp_tools_and_access(client):
    html = client.get("/services/demoapi").text
    card = html[html.index("<h2>MCP server</h2>"):]
    assert "3 tools" in card and "1 read · 1 write · 1 destructive" in card  # an unknown kind is left out
    assert "get_items" in card and "List items" in card and ">destructive<" in card
    assert "mcp · " in card[:400]


def test_service_without_test_path_warns_and_suggests(client):
    html = client.get("/services/demoapi").text
    assert "no test path" in html and 'value="/items?limit=1"' in html  # suggestion from the template of the same name


def test_save_test_path(client, app_module):
    import json
    from app import services_store
    before = services_store.read_raw("demoapi")
    try:
        r = client.post("/services/demoapi/test-path", data={"path": "/items?limit=1"}, headers={"HX-Request": "true"})
        assert r.headers.get("HX-Refresh") == "true"
        assert json.loads(services_store.read_raw("demoapi"))["test_path"] == "/items?limit=1"
        assert "no test path" not in client.get("/services/demoapi").text
        r = client.post("/services/demoapi/test-path", data={"path": "items; rm"}, headers={"HX-Request": "true"})
        assert "Not saved" in r.headers.get("HX-Trigger", "")
    finally:
        services_store.save_raw("demoapi", before)


def test_rename_route(client, app_module):
    import json
    from app import services_store
    before = services_store.read_raw("demodb")
    try:
        r = client.post("/services/demodb/rename", data={"new": "demodb2"}, headers={"HX-Request": "true"})
        assert r.headers.get("HX-Redirect") == "/services/demodb2"
        assert json.loads(services_store.read_raw("demodb2"))["name"] == "demodb2"
        assert client.get("/services/demodb2").status_code == 200
    finally:
        try:
            services_store.delete("demodb2")
        except FileNotFoundError:
            pass
        services_store.save_raw("demodb", before)


def test_rename_git_service_needs_running_sandbox(client, app_module):
    from app import dockerops, services_store
    if dockerops.status().get("running"):
        return  # the "running" variant would move files in a sandbox – only the refusal is tested here
    r = client.post("/services/demogit/rename", data={"new": "demogit2"}, headers={"HX-Request": "true"})
    assert "start tentaclAI first" in r.headers.get("HX-Trigger", "")
    services_store.read_raw("demogit")  # still there


def test_template_placeholder_domain(client, app_module):
    import json
    from app import services_store
    try:
        services_store.create("fromtpl", "n8n")
        assert json.loads(services_store.read_raw("fromtpl"))["api"]["base_url"] == "https://n8n.example.com"  # not the site's domain
        assert "placeholder address" in client.get("/services/fromtpl").text
        assert "placeholder address" not in client.get("/services/demoapi").text
    finally:
        services_store.delete("fromtpl")


def test_template_setup_hint_is_shown_not_saved(client, app_module):
    # the setup hint is for the user creating the service – Claude would read it in the notes after every onboarding
    import json
    from app import services_store
    try:
        r = client.post("/services/new", data={"name": "fromsetup", "template": "n8n"}, headers={"HX-Request": "true"})
        assert r.headers.get("HX-Redirect") == "/services/fromsetup"
        assert "Setup: token" in client.get("/services/fromsetup").text  # the flash message (fixture template)
        assert not any("Setup" in n for n in json.loads(services_store.read_raw("fromsetup")).get("notes") or [])
    finally:
        services_store.delete("fromsetup")


def test_templates_keep_setup_out_of_notes():
    import glob, json, os
    from conftest import ROOT
    for f in glob.glob(os.path.join(ROOT, "services", "_templates", "*.json")):
        for n in json.load(open(f)).get("notes") or []:
            assert not n.startswith("Setup") and "create a token" not in n, f"{os.path.basename(f)}: setup hint in notes"


def test_shared_variable_is_shown(client, app_module):
    from app import services_store as s
    try:
        s.create("tokone", "tokapi")
        s.create("tokrepo2", "tokgit")
        html = client.get("/services/tokone").text
        assert "Also used by" in html and 'href="/services/tokrepo2"' in html
    finally:
        for n in ("tokone", "tokrepo2"):
            s.delete(n)


def _as(monkeypatch, who):
    """make the TestClient's address ("testclient") look like the sandbox or the gateway"""
    from app import netguard
    from app.config import CLAUDE_CONTAINER
    name = {"sandbox": CLAUDE_CONTAINER, "egress": netguard.EGRESS_NAME}.get(who)
    monkeypatch.setattr(netguard, "_resolve", lambda n: {"testclient"} if n == name else set())


def test_sandbox_reaches_only_the_svc_endpoints(logged_in, monkeypatch):
    _as(monkeypatch, "sandbox")
    for path in ("/", "/login", "/settings", "/skills", "/internal/egress/policy"):
        assert logged_in.get(path, follow_redirects=False).status_code == 403, path  # even with a valid session
    assert logged_in.post("/internal/egress/ask", json={"host": "evil.test", "port": 443}).status_code == 403
    r = logged_in.get("/internal/approvals")  # reaches the endpoint – which still wants the svc token
    assert r.status_code != 403 or "not from here" not in r.text


def test_gateway_reaches_only_egress_endpoints(logged_in, monkeypatch):
    _as(monkeypatch, "egress")
    assert logged_in.get("/internal/egress/policy").status_code == 200
    assert logged_in.get("/settings", follow_redirects=False).status_code == 403
    assert logged_in.get("/internal/approvals").status_code == 403
    for path in ("/internal/egress/policy", "/internal/egress/wait/x?wait=0"):  # never through the reverse proxy
        assert logged_in.get(path, headers={"x-forwarded-for": "10.0.0.1"}).status_code == 403, path


def test_others_cant_use_egress_endpoints(logged_in, monkeypatch):
    _as(monkeypatch, "nobody")
    assert logged_in.get("/internal/egress/policy").status_code == 403
    assert logged_in.post("/internal/egress/ask", json={"host": "x.test", "port": 443}).status_code == 403
    assert logged_in.get("/settings").status_code == 200


@pytest.mark.parametrize("version,expect", [(None, "not running"), ("0.0.1", "still runs 0.0.1"), ("same", "applying it in the sandbox failed")])
def test_not_applied_message(logged_in, app_module, monkeypatch, version, expect):
    from app import dockerops, models
    monkeypatch.setattr(dockerops, "sandbox_version", lambda: app_module.TC_VERSION if version == "same" else version)
    monkeypatch.setattr(models, "set_values", lambda form: False)
    r = logged_in.post("/models", data={}, headers={"HX-Request": "true"})
    assert r.headers.get("HX-Refresh") == "true"
    assert expect in logged_in.get("/models").text  # flash message after the refresh


def test_credential_values_never_reach_the_browser(client):
    """ODD_ACCESS has no secret-looking name, but credsvc uses it as a header token"""
    for path in ("/settings", "/services/credsvc"):
        assert "visible-if-broken-123" not in client.get(path).text, path


def test_approval_shows_where_it_came_from(client, app_module):
    from app import activity
    rid = activity.create("demohost", "docker", "docker restart x", {"tmux": "claude-onboard-demohost"})
    try:
        html = client.get("/partials/approvals").text
        assert "from Onboarding demohost" in html
    finally:
        activity.decide(rid, False)


def test_network_decision_lands_in_the_audit_log(client, app_module, tmp_path, monkeypatch):
    """svc never sees the gateway's requests – tentacontrol logs the decision itself"""
    import json
    from app import activity, egress
    from app import auditlog
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(egress, "add", lambda kind, entry: None)
    monkeypatch.setattr(activity, "GRANTS", {})  # the "+ 10 min" below must not outlive the test
    rid = activity.create("evil.test:443", "network", "connect")
    client.post(f"/approvals/{rid}/block")
    rid2 = activity.create("api.test:443", "network", "connect")
    client.post(f"/approvals/{rid2}/net10")
    e = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [(x["service"], x["part"], x["decision"]) for x in e] == [("evil.test:443", "network", "blocked"), ("api.test:443", "network", "approved")]
    assert (e[0]["approver"], e[0]["grant"], e[1]["approver"], e[1]["grant"]) == ("admin", "blocklist", "admin", "10 min")
    assert {x["category"] for x in e} == {"network"} and e[0]["actor"] == "claude"
    html = client.get("/logs?since=all").text
    assert "evil.test:443" in html and "not run" not in html
    recent = client.get("/partials/approvals-recent").text  # Recent requests (from the audit log) names the lasting choice
    assert "evil.test:443" in recent and ">blocked</span>" in recent and "on the blocklist" in recent and ">admin</td>" in recent
    assert "api.test:443" in recent and ">approved</span>" in recent and "+ 10 min" in recent
    assert activity.APPROVALS[rid]["status"] == "denied"
    html = client.get("/logs?q=approver:admin&range=all").text  # a search field and a facet
    assert "evil.test:443" in html and '<span class="facet-name">admin</span>' in html
    r = client.get("/activity", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/approvals"
    html = client.get("/approvals").text
    assert "<h1>Approvals</h1>" in html and 'href="/approvals" class="active"' in html and "/partials/approvals-recent" in html


def test_flagged_entry_shows_what_was_found(client, app_module, tmp_path, monkeypatch):
    import json
    import time
    from app import auditlog
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    (tmp_path / "audit.jsonl").write_text(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "service": "Read", "part": "claude", "mode": "read",
        "action": "tool result: Read /workspace/notes.md", "decision": "flagged", "detail": "asks to ignore instructions",
        "excerpts": [{"reason": "asks to ignore instructions", "text": "line 4: <b>ignore</b> previous instructions"}]}) + "\n")
    html = client.get("/logs").text
    assert "Indicators" in html and "line 4: &lt;b&gt;ignore&lt;/b&gt; previous instructions" in html
    assert '>flagged</span>' in html and "asks to ignore instructions" in html
    assert "notes.md" in client.get("/logs?q=previous+instructions").text  # the excerpts are searchable


def test_flag_badge_until_the_audit_log_is_opened(client, app_module, tmp_path, monkeypatch):
    import json
    import time
    from app import activity, auditlog
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(auditlog, "FLAGS_SEEN", str(tmp_path / "flags-seen.json"))
    monkeypatch.setattr(auditlog, "_flags", {"ino": None, "pos": 0, "times": []})
    monkeypatch.setattr(activity, "APPROVALS", {})
    def flag(ts):
        with open(tmp_path / "audit.jsonl", "a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)), "service": "Read", "part": "claude",
                                "mode": "read", "action": "tool result: Read /x", "decision": "flagged", "detail": "addresses an AI agent"}) + "\n")
    flag(time.time() - 60)
    assert auditlog.unseen_flags() == 0  # the first call starts counting now – older entries don't light it up
    auditlog.jsonstore.save(auditlog.FLAGS_SEEN, {"ts": time.time() - 30})
    flag(time.time())
    badge = client.get("/partials/logs-count").text
    assert 'nav-badge warn' in badge and "⚠ 1" in badge
    assert "hidden" in client.get("/partials/approval-count").text  # the Activity badge is for approvals only
    assert "1 possible prompt injection" in client.get("/partials/overview").text
    client.get("/logs")
    assert "hidden" in client.get("/partials/logs-count").text and auditlog.unseen_flags() == 0
    assert "possible prompt injection" not in client.get("/partials/overview").text


def test_favicon_without_login(app_module):
    from fastapi.testclient import TestClient
    c = TestClient(app_module.app)
    for path in ("/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content[:4] == b"\x89PNG", path


def test_badge_disappears_after_the_last_decision(client, app_module):
    """an empty answer would be kept by app.js – the badge must answer with a hidden element"""
    from app import activity
    rid = activity.create("demohost", "docker", "docker restart x")
    assert ">1<" in client.get("/partials/approval-count").text.replace(" ", "")
    activity.decide(rid, False)
    r = client.get("/partials/approval-count").text
    assert r.strip() and "hidden" in r


def test_approval_banner(client, app_module):
    from app import activity
    assert 'id="approval-banner"' in client.get("/settings").text      # placeholder on normal pages
    assert 'id="approval-banner"' not in client.get("/approvals").text  # Approvals has the full list
    empty = client.get("/partials/approval-banner").text
    assert 'id="approval-banner"' in empty and "Approval needed" not in empty  # never an empty answer
    rid = activity.create("demohost", "docker", "docker restart x", {"tmux": "claude-rc"})
    html = client.get("/partials/approval-banner").text
    assert "Approval needed: demohost" in html and "from Remote Control" in html and f"/approvals/{rid}/approve?view=banner" in html
    r = client.post(f"/approvals/{rid}/deny?view=banner")
    assert 'id="approval-banner"' in r.text and "Approval needed" not in r.text and "Active grants" not in r.text
    assert activity.APPROVALS[rid]["status"] == "denied"


def test_same_session_asks_again_for_the_same_request(client, app_module, monkeypatch):
    """svc hands a pending approval back after APPROVAL_HANDOFF s – the same command again waits for the same request,
    a decision made meanwhile is used once, another session or another action gets a request of its own"""
    import asyncio
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    me, other = {"session": "11111111-2222-3333-4444-555555555555"}, {"session": "66666666-7777-8888-9999-000000000000"}
    rid = activity.create("demohost", "docker", "docker restart x", me)
    assert activity.create("demohost", "docker", "docker restart x", me) == rid and activity.APPROVALS[rid].pop("again")
    assert activity.create("demohost", "docker", "docker restart x", other) != rid
    assert activity.create("demohost", "docker", "docker restart y", me) != rid
    assert activity.create("demohost", "docker", "docker restart x", {}) != rid  # no session: never shared
    activity.decide(rid, True)
    again = activity.create("demohost", "docker", "docker restart x", me)  # decided while svc was handed back
    assert again == rid and activity.use(activity.APPROVALS[rid])["status"] == "approved"
    assert asyncio.run(activity.wait(rid, 1))["status"] == "error"  # used – a second call runs nothing
    assert activity.create("demohost", "docker", "docker restart x", me) != rid  # the next identical write asks anew


def test_risky_write_is_not_covered_by_a_grant(client, app_module, monkeypatch):
    """a grant ("Approve + 15 min") approves ordinary writes at once – a risky one still waits, marked in red, and
    a Docker approval says it is as much as root on that host"""
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    monkeypatch.setattr(activity, "GRANTS", {})
    first = activity.create("demohost", "docker", "docker restart web")
    activity.decide(first, True, grant=True)
    ok = activity.APPROVALS[activity.create("demohost", "docker", "docker restart db")]
    assert ok["status"] == "approved" and ok["grant"].startswith("until") and ok["risks"] == []
    risky = activity.APPROVALS[activity.create("demohost", "docker", "docker run --privileged -v /:/host alpine")]
    assert risky["status"] == "pending" and risky["grant_skipped"] and len(risky["risks"]) == 2
    assert risky["power"].startswith("Docker on ") and "root" in risky["power"]
    html = client.get("/partials/approvals").text
    assert "⚠ Risky: privileged container" in html and "asked although a grant is active" in html and "same as root" in html
    assert "⚠ risky" in client.get("/partials/approval-banner").text


def test_network_decision_reaches_every_waiting_connection(app_module, monkeypatch):
    """the gateway's connections to one target share a request – each of them learns the decision, again and again"""
    import asyncio
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    monkeypatch.setattr(activity, "GRANTS", {})
    rid = activity.create("example.org:443", "network", "connect")
    assert asyncio.run(activity.wait(rid, 1))["status"] == "pending"
    activity.decide(rid, True, grant=True, seconds=600)
    assert [asyncio.run(activity.wait(rid, 1))["status"] for _ in range(3)] == ["approved"] * 3


def test_internal_create_reports_a_request_asked_again(app_module, monkeypatch):
    from fastapi.testclient import TestClient
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    monkeypatch.setattr(activity, "token_ok", lambda v: v == "t")
    c = TestClient(app_module.app, client=("172.30.0.5", 1))
    body = {"service": "demohost", "part": "docker", "action": "docker restart z",
            "origin": {"session": "11111111-2222-3333-4444-555555555555"}}
    first = c.post("/internal/approvals", json=body, headers={"x-tc-token": "t"})
    if first.status_code == 403:  # netguard: the test client's address isn't the sandbox here – the logic is covered above
        return
    first = first.json()
    second = c.post("/internal/approvals", json=body, headers={"x-tc-token": "t"}).json()
    assert first["status"] == "pending" and not first["again"] and second["id"] == first["id"] and second["again"]


def test_approvals_watch(client, app_module, monkeypatch):
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    d = client.get("/approvals/watch?wait=0").json()
    assert d["sig"].startswith(activity.BOOT + ":") and d["boot"] == activity.BOOT
    rid = activity.create("demohost", "docker", "docker restart x", {"tmux": "claude-rc"})
    d2 = client.get("/approvals/watch?wait=5&seen=" + d["sig"]).json()  # changed: answers at once
    assert d2["sig"] != d["sig"] and [a["id"] for a in d2["pending"]] == [rid] and d2["pending"][0]["from"] == "Remote Control"
    activity.decide(rid, False)
    assert 'id="a-' not in client.get("/partials/approvals").text
    assert "data-desktop-notify" in client.get("/approvals").text


def test_netguard_does_not_cache_a_failed_lookup(app_module, monkeypatch):
    """a sandbox not yet in Docker's DNS must be recognised by its next request, not after the cache expires"""
    from app import netguard
    from app.config import CLAUDE_CONTAINER
    calls = []
    def fake(name, port):
        if name != CLAUDE_CONTAINER:
            raise OSError("no such host")
        calls.append(name)
        if len(calls) == 1:
            raise OSError("not yet in Docker's DNS")
        return [(0, 0, 0, "", ("172.30.0.5", 0))]
    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake)
    monkeypatch.setattr(netguard, "_cache", {})
    assert netguard.source("172.30.0.5") == "other"  # lookup failed
    assert netguard.source("172.30.0.5") == "sandbox"  # asked again right away


def test_netguard_unknown_address_in_the_sandbox_network_counts_as_sandbox(app_module, monkeypatch):
    import ipaddress
    from app import netguard
    monkeypatch.setattr(netguard, "_resolve", lambda n: {"10.9.0.3"} if n == netguard.EGRESS_NAME else set())
    monkeypatch.setattr(netguard, "_sandbox_nets", lambda: [ipaddress.ip_network("10.9.0.0/24")])
    assert netguard.source("10.9.0.7") == "sandbox"  # sandbox name lookup failed – still not "anyone else"
    assert netguard.source("10.9.0.3") == "egress"
    assert netguard.source("192.168.1.5") == "other"
    assert not netguard.allowed("/login", "10.9.0.7")


def test_job_pages_render(client, app_module, monkeypatch, tmp_path):
    from app import scheduled
    monkeypatch.setattr(scheduled, "JOBS", str(tmp_path / "jobs.json"))
    monkeypatch.setattr(scheduled, "HISTORY", str(tmp_path / "hist.json"))
    jid = scheduled.save({"name": "Disk space", "prompt": "df", "kind": "cron", "expr": "0 7 * * 1-5", "profile": "standard"})
    from app import jsonstore
    jsonstore.save(scheduled.HISTORY, [{"id": "abc123", "job": jid, "name": "Disk space", "status": "done", "queued": 1,
                                        "result": {"status": "warn", "title": "80 % on /", "summary": "s", "details": "d"}}])
    for path in ("/jobs", f"/jobs/{jid}", "/jobs/new?template=1"):
        r = client.get(path)
        assert r.status_code == 200 and "</html>" in r.text, path
    assert "80 % on /" in client.get("/jobs").text


def test_job_badge_counts_unseen_findings(client, app_module, monkeypatch, tmp_path):
    import time
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    now = time.time()
    jsonstore.save(scheduled.HISTORY, [
        {"id": "a1", "job": "x", "status": "done", "ended": now, "result": {"status": "ok"}},
        {"id": "a2", "job": "x", "status": "done", "ended": now, "result": {"status": "alert"}},
        {"id": "a3", "job": "x", "status": "failed", "ended": now}])
    assert ">2<" in client.get("/partials/job-count").text
    client.get("/jobs")  # opening the page marks them seen
    assert "hidden" in client.get("/partials/job-count").text
    r = client.get("/claude/jobs", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/jobs"
    assert scheduled.slug("New") == "new-job" and scheduled.slug("Runs") == "runs-job"


def test_jobs_show_latest_run_and_fold_the_rest(client, app_module, monkeypatch, tmp_path):
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "Disk space", "prompt": "df", "kind": "daily", "time": "06:30"})
    jsonstore.save(scheduled.HISTORY, [{"id": f"r{i}", "job": jid, "name": "x", "status": "done", "queued": i,
                                        "result": {"status": "ok", "title": f"title {i}"}} for i in range(3)])
    html = client.get("/jobs").text
    assert "History (2 earlier runs)" in html and html.index("title 2") < html.index("job-history") < html.index("title 1")


def test_manual_job_renders_without_next_and_pause(client, app_module, monkeypatch, tmp_path):
    from app import scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "On demand", "prompt": "p", "kind": "manual"})
    html = client.get("/jobs").text
    card = html[html.index("On demand"):]
    assert "manual" in card and "· next" not in card[:400] and 'role="switch"' not in card[:2500]
    assert client.get(f"/jobs/{jid}").status_code == 200


def test_run_log_partial(client, app_module, monkeypatch, tmp_path):
    from app import jsonstore, scheduled
    for k, f in (("HISTORY", "h.json"), ("LOGS", "logs")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jsonstore.save(scheduled.HISTORY, [{"id": "abc123", "job": "x", "status": "running", "queued": 1}])
    jsonstore.save(scheduled.log_path("abc123"), [{"t": 1, "k": "tool", "s": "Bash  svc mail mailrelay send"}, {"t": 2, "k": "err", "s": "boom <b>"}])
    html = client.get("/jobs/runs/abc123/log").text
    assert "svc mail mailrelay send" in html and "jl-err" in html and "&lt;b&gt;" in html and "…" in html
    assert "No steps recorded" in client.get("/jobs/runs/zzz999/log").text


def test_settings_show_default_job_helpers(client):
    from app import scheduled
    html = client.get("/settings").text
    assert 'placeholder="default: ' + ", ".join(scheduled.HELPERS_DEFAULT) + '"' in html
    assert html.count('class="field wide"') == 3  # APPROVAL_HANDOFF, JOB_READONLY_HELPERS, INJECTION_GUARD: long help, whole row


def test_settings_refuse_dangerous_job_helpers(client):
    r = client.post("/settings", data={"k_JOB_READONLY_HELPERS": "head, bash, curl"}, headers={"HX-Request": "true"})
    assert "Helpers refused" in r.headers.get("HX-Trigger", "") and "bash, curl" in r.headers.get("HX-Trigger", "")


def test_internal_svc_endpoints_need_the_svc_token(client, app_module):
    from fastapi.testclient import TestClient
    c = TestClient(app_module.app)
    for path in ("/internal/jobs/check", "/internal/jobs/put", "/internal/approvals", "/internal/event"):
        assert c.post(path, json={"name": "x", "definition": {}}).status_code == 403, path
    for path in ("/internal/approvals", "/internal/approvals/x?wait=0"):
        assert c.get(path).status_code == 403, path


def test_job_proposals_render(client, app_module, monkeypatch, tmp_path):
    import time
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "Spam check", "prompt": "p", "kind": "manual", "propose": "1"})
    acts = [{"title": "move spam 912", "command": "svc mail box move 912 Junk", "state": "proposed"},
            {"title": "move spam 913", "command": "svc mail box move 913 Junk", "state": "done", "output": "✓ moved"}]
    jsonstore.save(scheduled.HISTORY, [{"id": "r1", "job": jid, "name": "x", "status": "done", "queued": 1, "ended": 2,
                                        "actions": acts, "actions_until": time.time() + 3600, "result": {"status": "warn", "title": "2 spam"}}])
    html = client.get("/jobs").text
    assert "Run selected" in html and 'name="pick" value="0"' in html and "proposes" in html and "✓ moved" in html
    jsonstore.save(scheduled.HISTORY, [dict(scheduled.history()[0], actions_until=time.time() - 1)])
    html = client.get("/jobs").text
    assert "Run selected" not in html and "expired" in html
    assert "Propose actions" in client.get(f"/jobs/{jid}").text


def test_prompt_suggestion_shows_a_diff(client, app_module, monkeypatch, tmp_path):
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "Disk check", "prompt": "check the disks", "kind": "manual"})
    sugg = {"text": "check the disks of all hosts", "why": "hosts were unclear", "state": "proposed", "base": "check the disks"}
    jsonstore.save(scheduled.HISTORY, [{"id": "r1", "job": jid, "name": "x", "status": "done", "queued": 1, "ended": 2,
                                        "prompt_suggestion": sugg, "result": {"status": "ok", "title": "t"}}])
    html = client.get("/jobs").text
    assert "3 → 6 words" in html and '<ins class="diff-add"> of all hosts</ins>' in html and "Use this task" in html
    jsonstore.save(scheduled.HISTORY, [dict(scheduled.history()[0], prompt_suggestion={k: v for k, v in sugg.items() if k != "base"})])
    html = client.get("/jobs").text  # a suggestion from before the diff: the whole text as before
    assert "the suggested task" in html and "diff-add" not in html


def test_job_tabs_render_and_move(client, app_module, monkeypatch, tmp_path):
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    a = scheduled.save({"name": "Spam check", "prompt": "p", "kind": "manual", "group": "Spam"})
    b = scheduled.save({"name": "Disk check", "prompt": "p", "kind": "manual"})
    jsonstore.save(scheduled.HISTORY, [{"id": "r1", "job": a, "name": "x", "status": "done", "queued": 1, "ended": 2,
                                        "result": {"status": "alert", "title": "t"}}])
    html = client.get("/jobs?tab=*").text
    assert 'class="tabs job-tabs"' in html and "Spam check" in html and "Disk check" in html and "No group" in html
    assert '<option value="Spam" selected>Spam</option>' in html and "New group…" in html  # the move menu
    assert 'title="1 job with alert in the last run"' in html
    html = client.get("/jobs?tab=Spam").text
    assert "Spam check" in html and "Disk check" not in html and "/jobs/new?group=Spam" in html
    assert "Disk check" not in client.get("/jobs").text  # the picked tab is remembered
    r = client.post(f"/jobs/{b}/group", data={"group": "spam"}, headers={"HX-Request": "true"})
    assert scheduled.get(b)["group"] == "Spam" and r.headers.get("HX-Refresh") == "true"
    assert "Moved to the group Spam" in client.get("/jobs").text  # the flash message
    assert 'data-group="Spam"' in client.get(f"/jobs/{a}").text  # the editor offers the existing groups
    r = client.post(f"/jobs/{a}/group", data={"group": "*"}, headers={"HX-Request": "true"})  # refused: reload
    assert scheduled.get(a)["group"] == "Spam" and r.headers.get("HX-Refresh") == "true"
    assert "Not moved:" in client.get("/jobs").text  # the select is rendered with the old group again
    client.post(f"/jobs/{a}/group", data={"group": ""}, headers={"HX-Request": "true"})
    client.post(f"/jobs/{b}/group", data={"group": ""}, headers={"HX-Request": "true"})
    html = client.get("/jobs").text  # no tab in use: no tab bar, all jobs
    assert "job-tabs" not in html and "Spam check" in html and "Disk check" in html
    html = client.get("/jobs/new?group=Spam").text
    assert 'name="group"' in html and 'value="Spam"' in html and "Group" in html


def test_pending_proposals_show_outside_the_folded_run(client, app_module, monkeypatch, tmp_path):
    import time
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "Spam", "prompt": "p", "kind": "manual", "propose": "1"})
    run = {"id": "r1", "job": jid, "name": "x", "status": "done", "queued": 1, "ended": 2, "result": {"status": "warn", "title": "t"},
           "actions": [{"title": "a", "command": "svc mail b move 1 Junk", "state": "proposed"}], "actions_until": time.time() + 600}
    jsonstore.save(scheduled.HISTORY, [run])
    html = client.get("/jobs").text
    assert "job-pending" in html and html.index("</details>") < html.index("Run selected")  # below the row, not inside it
    for changed in ({"actions_until": time.time() - 1}, {"actions": [dict(run["actions"][0], state="done")]}):
        jsonstore.save(scheduled.HISTORY, [dict(run, **changed)])
        html = client.get("/jobs").text
        assert '<div class="job-pending">' not in html  # expired or settled: inside the row again


def test_job_badge_prefers_waiting_proposals(client, app_module, monkeypatch, tmp_path):
    import time
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    acts = [{"title": "a", "command": "svc m move 1 Junk", "state": "proposed"}, {"title": "b", "command": "svc m move 2 Junk", "state": "proposed"},
            {"title": "c", "command": "svc m move 3 Junk", "state": "done"}]
    jsonstore.save(scheduled.HISTORY, [{"id": "r1", "job": "x", "status": "done", "ended": time.time() - 100, "result": {"status": "warn"},
                                        "actions": acts, "actions_until": time.time() + 600}])
    b = client.get("/partials/job-count").text
    assert ">2<" in b and "warn" not in b  # pulsing, the count of proposals
    client.get("/jobs")  # looking doesn't decide anything
    assert ">2<" in client.get("/partials/job-count").text
    jsonstore.save(scheduled.HISTORY, [{"id": "r1", "job": "x", "status": "done", "ended": time.time() - 100, "result": {"status": "warn"},
                                        "actions": acts, "actions_until": time.time() - 1}])
    assert "hidden" in client.get("/partials/job-count").text  # expired, and the finding was seen


def test_discard_buttons_and_route(client, app_module, monkeypatch, tmp_path):
    import time
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "Spam", "prompt": "p", "kind": "manual", "propose": "1"})
    acts = [{"title": "a", "command": "svc m move 1 Junk", "state": "proposed"}, {"title": "b", "command": "svc m move 2 Junk", "state": "proposed"}]
    jsonstore.save(scheduled.HISTORY, [{"id": "r1", "job": jid, "name": "x", "status": "done", "queued": 1, "ended": 2,
                                        "actions": acts, "actions_until": time.time() + 600, "result": {"status": "warn", "title": "t"}}])
    html = client.get("/jobs").text
    assert "Discard selected" in html and "Discard all" in html
    client.post("/jobs/runs/r1/discard", data={"pick": ["1"]}, headers={"HX-Request": "true"})
    assert [a["state"] for a in scheduled.history()[0]["actions"]] == ["proposed", "discarded"]
    client.post("/jobs/runs/r1/discard?all=1", headers={"HX-Request": "true"})
    assert scheduled.pending_proposals() == 0


def test_paused_job_is_easy_to_tell(client, app_module, monkeypatch, tmp_path):
    from app import scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    on = scheduled.save({"name": "A on", "prompt": "p", "kind": "daily", "time": "06:30"})
    off = scheduled.save({"name": "B off", "prompt": "p", "kind": "daily", "time": "06:30"})
    scheduled.set_enabled(off, False)
    html = client.get("/jobs").text
    a, b = html[html.index("A on"):html.index("B off")], html[html.index("B off"):]
    assert 'aria-checked="true"' in a and "next " in a and "job-card paused" not in html[:html.index("A on")][-300:]
    assert 'aria-checked="false"' in b and "no automatic runs" in b and "job-card paused" in html[html.index("A on"):html.index("B off")]


def test_service_cards_are_compact(client):
    html = client.get("/services").text
    card = html[html.index('href="/services/demodb" title="Edit demodb"'):]
    card = card[:card.index('class="card service-card')]
    assert "db · read" in card and "token missing" in card and "DB_PW" in card  # problems stay visible by name
    assert ">active<" not in html  # the green dot says it already
    assert 'hx-post="/services/demodb/toggle"' in card and 'class="menu-item"' in card  # Disable lives in the … menu


def test_mailbox_name_address_and_another_mailbox(client, app_module):
    import json
    import os
    import shutil
    from app import services_store
    from app.envfile import read_env
    assert services_store.suggest_name("Root@bitbunker.at") == "mail-root-bitbunker"
    assert services_store.suggest_name("a.b+c@x.y.z") == "mail-a-b-c-x"
    tpl = os.path.join(services_store.TEMPLATES_DIR, "mail-imap.json")
    shutil.copy(os.path.join(os.path.dirname(__file__), "..", "services", "_templates", "mail-imap.json"), tpl)
    try:
        r = client.post("/services/new", data={"name": "mail-root-bit", "template": "mail-imap", "address": "root@bit.test"},
                        headers={"HX-Request": "true"})
        assert r.headers.get("HX-Redirect") == "/services/mail-root-bit"
        d = json.loads(services_store.read_raw("mail-root-bit"))
        assert d["imap"]["host"] == "imap.bit.test" and d["smtp"]["from"] == "root@bit.test"
        user_var = d["imap"]["user"][2:-1]
        assert read_env()[user_var] == "root@bit.test"
        d["system"] = "box"
        services_store.save_raw("mail-root-bit", json.dumps(d))
        html = client.get("/services").text
        assert "root@bit.test" in html and "/services?like=mail-root-bit" in html
        form = client.get("/services?like=mail-root-bit").text
        assert "Another mailbox on the server of" in form and "joins system <strong>box</strong>" in form
        assert "Another mailbox" not in client.get("/services?like=demoapi").text.split('id="new-svc"')[1][:400]
        r = client.post("/services/new", data={"name": "mail-info-bit", "like": "mail-root-bit", "address": "info@bit.test"},
                        headers={"HX-Request": "true"})
        assert r.headers.get("HX-Redirect") == "/services/mail-info-bit"
        c = json.loads(services_store.read_raw("mail-info-bit"))
        assert c["imap"]["host"] == "imap.bit.test" and c["system"] == "box" and c["description"] == "Mailbox info@bit.test"
        assert c["imap"]["user"] != d["imap"]["user"] and c["imap"]["user"].startswith("${MAIL_INFO_BIT_")
        assert c["imap"]["password"].startswith("${MAIL_INFO_BIT_") and c["smtp"]["from"] == "info@bit.test"
        assert read_env()[c["imap"]["user"][2:-1]] == "info@bit.test"
        r = client.post("/services/new", data={"name": "x1", "like": "mail-root-bit", "address": "nope"}, headers={"HX-Request": "true"})
        assert not r.headers.get("HX-Redirect")
        r = client.post("/services/new", data={"name": "x2", "like": "demoapi", "address": "a@b.test"}, headers={"HX-Request": "true"})
        assert not r.headers.get("HX-Redirect")
    finally:
        os.remove(tpl)
        for n in ("mail-root-bit", "mail-info-bit"):
            if os.path.exists(services_store.path_of(n)):
                services_store.delete(n)


def test_network_seen_table_is_sortable(client, monkeypatch):
    from app import egress
    rows = [{"host": "api.example.com", "port": 443, "kind": "tentacle", "label": "demo", "decision": "tentacle", "count": 7, "first": 1, "last": 200},
            {"host": "odd.example.net", "port": 80, "kind": "unknown", "label": "", "decision": "unlisted", "count": 2, "first": 1, "last": 300}]
    monkeypatch.setattr(egress, "seen_rows", lambda: [dict(r) for r in rows])
    html = client.get("/network").text
    for key in ("host", "rule", "decision", "count", "last"):
        assert f'data-sort="{key}"' in html
    assert 'aria-sort="descending"' in html  # newest first, as the server sorts
    assert 'data-count="7" data-last="200"' in html and 'data-rule="0"' in html and 'data-rule="2demo"' in html


def test_add_host_also_adds_the_docker_service(client, app_module, monkeypatch):
    """Add host with "Docker host" ticked: after the login works, docker is checked, the stacks directory found and a
    docker service created (access confirm); unticked, or without docker, no service"""
    import json
    import os
    import shutil
    from app import dockerops, services_store, sshhosts
    from conftest import ROOT, STACK
    shutil.copy(os.path.join(ROOT, "services", "_templates", "docker-ssh.json"), os.path.join(STACK, "services", "_templates"))
    monkeypatch.setattr(dockerops, "ssh_check", lambda alias, sudo="": (0, f"root@{alias}\n"))
    ls = json.dumps([{"Name": "a", "ConfigFiles": "/srv/apps/a/compose.yaml"}, {"Name": "b", "ConfigFiles": "/srv/apps/b/compose.yaml"}])
    docker_ok = {"v": True}

    def ssh_run(alias, remote):
        if "docker version" in remote:
            return (0, "27.3.1\n") if docker_ok["v"] else (127, "bash: docker: command not found\n")
        return 0, ls
    monkeypatch.setattr(dockerops, "ssh_run", ssh_run)
    form = {"alias": "Nas.home", "hostname": "nas.example.test", "user": "root", "port": "22", "access": "confirm",
            "docker": "1", "mode": "skip"}
    try:
        html = client.post("/ssh/new/deploy", data=form).text
        assert "Docker 27.3.1 answers" in html and "stacks in /srv/apps (2 of 2" in html and "svc docker nas-home ps" in html
        d = json.loads(services_store.read_raw("nas-home"))["docker"]
        assert d == {"mode": "ssh", "ssh_host": "Nas.home", "stacks_dir": "/srv/apps", "access": "confirm"}
        html = client.post("/ssh/new/deploy", data=dict(form, alias="other", docker="")).text
        assert "Docker" not in html and "other" not in [s["name"] for s in services_store.load_all()]
        docker_ok["v"] = False
        html = client.post("/ssh/new/deploy", data=dict(form, alias="nodocker")).text
        assert "No Docker service created" in html and "nodocker" not in [s["name"] for s in services_store.load_all()]
        assert "This host" in client.get("/ssh/new").text and 'name="docker" value="1" checked' in client.get("/ssh/new").text
    finally:
        for a in ("Nas.home", "other", "nodocker"):
            if sshhosts.get(a):
                sshhosts.remove(a)
        if os.path.exists(services_store.path_of("nas-home")):
            services_store.delete("nas-home")


def test_network_learning_phase(client, monkeypatch, tmp_path):
    """EGRESS_MODE=learn: permissive until the phase (from the first reported connection) is over, then enforce in .env,
    a notification, and the destinations seen meanwhile without a rule offered for the allowlist"""
    import time
    from app import egress, notify
    env = {"EGRESS_MODE": "learn"}
    monkeypatch.setattr(egress, "read_env", lambda: env)
    monkeypatch.setattr(egress, "LEARN", str(tmp_path / "egress-learn.json"))
    monkeypatch.setattr("app.envfile.update_env", lambda ch: env.update(ch))
    sent, allowed = [], []
    monkeypatch.setattr(notify, "emit", lambda *a, **k: sent.append(a[0]))
    monkeypatch.setattr(egress, "add", lambda kind, e: allowed.append((kind, e)))
    now = time.time()
    rows = [{"host": "odd.example.net", "port": "443", "kind": "unknown", "label": "", "decision": "unlisted", "count": 2,
             "first": now - 100, "last": now - 50},
            {"host": "api.example.com", "port": "443", "kind": "tentacle", "label": "demo", "decision": "tentacle", "count": 1,
             "first": now - 100, "last": now - 50}]
    monkeypatch.setattr(egress, "seen_rows", lambda: [dict(r) for r in rows])
    assert egress.mode() == "permissive" and "first connection" in client.get("/network").text
    egress.learn_start()
    assert egress.mode() == "permissive" and "allowed and recorded until" in client.get("/network").text
    egress.jsonstore.save(egress.LEARN, {"started": now - 3700})  # the hour is over
    assert egress.mode() == "enforce" and env["EGRESS_MODE"] == "enforce" and sent == ["learned"]
    assert egress.mode() == "enforce" and sent == ["learned"]  # once
    html = client.get("/network").text
    assert "Learning phase over – 1 destination without a rule" in html and "odd.example.net:443" in html and "Allow all" in html
    assert egress.learned_allow() == 1 and allowed == [("allow", "odd.example.net:443")]
    assert egress.learned() == [] and "Learning phase over" not in client.get("/network").text


def test_audit_rows_have_details(client, app_module, tmp_path, monkeypatch):
    import json
    from app import auditlog
    f = tmp_path / "audit.jsonl"
    rows = [{"ts": "2026-10-22T10:00:00+0000", "service": "demohost", "part": "docker", "mode": "confirm",
             "action": "docker ps", "decision": "approved", "detail": "tentacontrol + 15 min"},
            {"ts": "2026-10-22T10:01:00+0000", "service": "demohost", "part": "docker", "mode": "confirm",
             "action": "compose up -d " + "x" * 120, "decision": "auto"}]
    f.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    html = client.get("/logs?range=all").text
    assert html.count("data-audit-row") == 2 and html.count('class="audit-detail" hidden') == 2
    assert "tentacontrol + 15 min" in html and "docker · confirm" in html and '&#34;decision&#34;: &#34;approved&#34;' in html  # fields + JSON


def test_audit_search_facets_and_histogram(client, app_module, tmp_path, monkeypatch):
    import json
    import time
    from app import auditlog
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    f = tmp_path / "audit.jsonl"
    rows = [{"ts": "2020-01-01T10:00:00+0000", "service": "demohost", "part": "docker", "mode": "write",
             "action": "compose old up -d", "decision": "auto", "exit": 0},
            {"ts": now, "service": "demohost", "part": "docker", "mode": "write", "action": "compose web up -d",
             "decision": "auto", "exit": 1, "error": "no such service: web", "from": {"tmux": "claude-workspace"}},
            {"ts": now, "service": "demoapi", "part": "api", "mode": "write", "action": "POST /items",
             "decision": "auto", "exit": 0, "from": {"by": "root"}}]
    f.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    html = client.get("/logs?range=all").text
    assert "no such service: web" in html and 'href="/terminal?p=claude"' in html and "compose old" in html
    assert ">failed</span>" in html and "3 events" in html and "<svg" in html  # outcome, count, histogram
    assert '<span class="tag" data-type="svc">' in html  # each type its own colour (table, detail, facets)
    html = client.get("/logs").text  # last 24 h by default
    assert "compose old" not in html and "POST /items" in html and "2 events" in html
    html = client.get("/logs?q=outcome:failed").text
    assert "compose web" in html and "POST /items" not in html and 'class="chip"' in html
    # facets: counted under the other terms – with outcome:failed chosen, auto still shows its number
    assert 'class="facet-v on"' in html and '<span class="facet-name">auto</span><span class="facet-n">1</span>' in html
    html = client.get("/logs?q=-target:demohost").text
    assert "POST /items" in html and "compose web" not in html and 'class="chip neg"' in html
    html = client.get("/logs?q=ITEMS").text
    assert "POST /items" in html and "compose web" not in html
    assert "Nothing matches" in client.get("/logs?q=nothing-like-this").text
    html = client.get("/logs?q=source:\"tentacontrol / host\"&range=all").text  # by root
    assert "POST /items" in html and "compose web" not in html
    html = client.get("/logs?q=target:demo*").text  # wildcard
    assert "POST /items" in html and "compose web" in html
    html = client.get("/logs?range=custom&from=2020-01-01T00:00&to=2020-01-01T23:59").text
    assert "compose old" in html and "POST /items" not in html and 'type="datetime-local"' in html
    # older links keep working
    html = client.get("/logs?actor=system&since=all").text
    assert "POST /items" in html and "compose web" not in html
    assert "compose old" in client.get("/logs?start=2020-01-01&end=2020-01-01").text
    html = client.get("/logs?service=demohost&decision=auto&since=all").text
    assert "compose web" in html and "POST /items" not in html and "target:</span> <span class=\"chip-v\">demohost" in html
    # values in rows and the histogram bars are links that narrow the search
    assert 'href="/logs?q=target%3Ademohost"' in client.get("/logs").text
    assert "range=custom&amp;from=" in client.get("/logs").text


def test_audit_load_more_and_export(client, app_module, tmp_path, monkeypatch):
    import csv
    import io
    import json
    import tclib
    from app import auditlog
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(auditlog, "PAGE", 3)
    for i in range(5):
        tclib.audit_write(str(tmp_path), tclib.audit_entry("tool", "Bash", f"echo step{i}", "ok", part="claude",
                                                           origin={"tmux": "claude-workspace"}))
    html = client.get("/logs").text
    assert "echo step4" in html and "echo step2" in html and "echo step1" not in html and "Load more" in html
    last = tclib.audit_read(str(tmp_path), limit=3)[0][-1]["id"]
    more = client.get(f"/logs/audit/more?after={last}").text
    assert "echo step1" in more and "echo step0" in more and "Load more" not in more and "<html" not in more
    r = client.get("/logs/audit/export?fmt=csv&q=step")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [x["action"] for x in rows] == [f"echo step{i}" for i in (4, 3, 2, 1, 0)] and rows[0]["actor"] == "claude"
    r = client.get("/logs/audit/export?fmt=jsonl&q=step3")
    assert [json.loads(x)["action"] for x in r.text.splitlines()] == ["echo step3"]
    exported = tclib.audit_read(str(tmp_path), query="type:admin")[0]
    assert exported and exported[0]["action"] == "export as jsonl" and exported[0]["actor"] == "user"  # the export is audited


def test_admin_actions_and_sign_in_are_audited(client, app_module, tmp_path, monkeypatch):
    import tclib
    from app import auditlog
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    client.post("/skills/mode", data={"name": "dataviz", "mode": "off"}, headers={"HX-Request": "true"})
    e = tclib.audit_read(str(tmp_path))[0]
    assert e[0]["category"] == "admin" and e[0]["action"] == "skills mode" and e[0]["actor"] == "user" and e[0]["user"] == "admin"
    assert e[0]["mode"] == "POST" and "POST /skills/mode" in e[0]["detail"] and "dataviz" not in str(e[0])  # never the form
    from fastapi.testclient import TestClient
    TestClient(app_module.app).post("/login", data={"username": "Mallory!", "password": "certainly-wrong"})
    bad = tclib.audit_read(str(tmp_path), query="type:auth")[0]
    assert bad and bad[0]["decision"] == "failed" and bad[0]["severity"] == 4 and bad[0]["user"] == "mallory"  # as typed, cleaned
    assert "certainly-wrong" not in str(bad)
    from app import auth
    auth.clear_failures("testclient")
    html = client.get("/logs").text
    assert '<span class="actor actor-user"><a class="audit-val" href="/logs?q=user%3Aadmin"' in html  # the username


def test_egress_audit_endpoint(client, app_module, tmp_path, monkeypatch):
    import tclib
    from app import auditlog, netguard
    monkeypatch.setattr(auditlog, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(netguard, "allowed", lambda path, ip: True)
    client.post("/internal/egress/audit", json={"entries": [
        {"host": "api.example.net", "port": 443, "decision": "allowed", "reason": "tentacle", "count": 7, "first": 1},
        {"host": "evil.test", "port": 22, "decision": "blocked", "reason": "blocked", "count": 1},
        {"host": "bad host!", "port": 1}]})
    e = tclib.audit_read(str(tmp_path), query="type:network")[0]
    assert [(x["service"], x["decision"], x.get("count")) for x in e] == [("evil.test:22", "blocked", 1), ("api.example.net:443", "allowed", 7)]
    assert {x["action"] for x in e} == {"connect"}  # the destination is the target, not repeated in the action
    html = client.get("/logs?range=all").text
    assert 'connect <span class="faint">· 7×</span>' in html and "· 1×" not in html


def test_log_containers_tabs(client):
    html = client.get("/logs/containers?c=egress").text
    assert "tentaclai-egress" in html and "/logs/stream?c=egress" in html and 'href="/logs/containers?c=control"' in html
    assert "/logs/stream?c=tentaclai" in client.get("/logs/containers?c=nonsense").text


def test_settings_other_vars_managed_elsewhere_and_remove(client):
    from app.envfile import read_env, update_env
    html = client.get("/settings").text
    assert 'name="k_NOTIFY_URL_PHONE"' not in html and "NOTIFY_URL_PHONE</span> → <a href=\"/notifications\">" in html
    update_env({"LEFTOVER_KEY": ""})
    assert 'name="remove_LEFTOVER_KEY"' in client.get("/settings").text
    r = client.post("/settings", data={"k_LEFTOVER_KEY": "", "remove_LEFTOVER_KEY": "on"}, headers={"HX-Request": "true"})
    assert r.status_code == 200
    env = read_env()
    assert "LEFTOVER_KEY" not in env and env.get("TC_HOSTNAME") == "testhost"
    update_env({"NOT_THERE": None})  # removing a missing key is a no-op, not an append
    assert "NOT_THERE" not in read_env()


def test_approval_shows_changes_and_takes_a_reason(client, app_module):
    from app import activity
    review = activity.clean_review('@@ -1 +1,2 @@\n   "notes": [\n+    "Restart only at night"', ["addresses an AI agent"])
    rid = activity.create("system gate", "config", "change systems/gate.json, +1/-0 lines", None, review)
    html = client.get("/partials/approvals").text
    assert 'class="diff-add">+    &#34;Restart only at night&#34;' in html and "possible prompt injection" in html
    assert 'name="reason"' in html and "⚠ check the changes" in client.get("/partials/approval-banner").text
    client.post(f"/approvals/{rid}/deny", data={"reason": "  not now,\n ask me first  "})
    a = activity.APPROVALS[rid]
    assert a["status"] == "denied" and activity.use(a)["reason"] == "not now, ask me first"


def test_denial_reason_in_the_audit_log(client, app_module, tmp_path, monkeypatch):
    import tclib
    monkeypatch.setattr(app_module.auditlog, "DATA_DIR", str(tmp_path))
    tclib.audit_write(str(tmp_path), tclib.audit_entry("service", "demohost", "docker restart web", "denied", actor="claude",
                                                       part="docker", mode="confirm", approver="admin", reason="only at night"))
    html = client.get("/logs?q=reason:\"only at night\"").text
    assert "“only at night”" in html and "docker restart web" in html
    assert "“only at night”" in client.get("/partials/approvals-recent").text  # Recent requests


def test_rename_and_delete_keep_jobs_in_the_picture(client, app_module, monkeypatch, tmp_path):
    from app import jsonstore, scheduled, services_store
    monkeypatch.setattr(scheduled, "JOBS", str(tmp_path / "jobs.json"))
    monkeypatch.setattr(scheduled, "HISTORY", str(tmp_path / "hist.json"))
    jsonstore.save(scheduled.JOBS, {"j1": {"name": "DB check", "prompt": "count rows with @demodb", "profile": "read-only",
                                          "schedule": {"kind": "manual"}, "notify": "findings"}})
    before = services_store.read_raw("demodb")
    try:
        client.post("/services/demodb/rename", data={"new": "demodb3"}, headers={"HX-Request": "true"})
        assert "updated the task of DB check" in client.get("/services/demodb3").text  # the flash message
        assert scheduled.get("j1")["prompt"] == "count rows with @demodb3"
        client.post("/services/demodb3/delete", headers={"HX-Request": "true"})
        assert "the task of DB check still names @demodb3" in client.get("/services").text
        assert "the task names @demodb3, which no longer exists" in client.get("/jobs").text
    finally:
        for n in ("demodb3",):
            try:
                services_store.delete(n)
            except FileNotFoundError:
                pass
        services_store.save_raw("demodb", before)


def test_jobs_page_lists_what_the_badge_counted(client, app_module, monkeypatch, tmp_path):
    """the badge counts findings of every run since the last visit – the page shows those runs, also from the history"""
    import time
    from app import jsonstore, scheduled
    for k, f in (("JOBS", "j.json"), ("HISTORY", "h.json"), ("SEEN", "s.json")):
        monkeypatch.setattr(scheduled, k, str(tmp_path / f))
    jid = scheduled.save({"name": "Disk space", "prompt": "df", "kind": "daily", "time": "06:30"})
    now = time.time()
    jsonstore.save(scheduled.SEEN, {"ts": now - 7200})
    jsonstore.save(scheduled.HISTORY, [
        {"id": "old1", "job": jid, "status": "done", "queued": now - 9000, "ended": now - 9000, "result": {"status": "alert", "title": "seen before"}},
        {"id": "new1", "job": jid, "status": "done", "queued": now - 3600, "ended": now - 3600, "result": {"status": "warn", "title": "90 % on /"}},
        {"id": "new2", "job": jid, "status": "done", "queued": now - 60, "ended": now - 60, "result": {"status": "ok", "title": "fine again"}}])
    html = client.get("/jobs").text
    box = html[html.index("New since your last visit"):html.index("job-card")]
    assert 'href="#run-new1"' in box and "Disk space</strong> – 90 % on /" in box and "seen before" not in box and "fine again" not in box
    assert '<details class="job-history" open>' in html and '<details class="mem-entry" id="run-new1" open>' in html
    assert "New since your last visit" in client.get("/jobs").text  # a reload (auto refresh) still shows it
    r = client.post("/jobs/seen", headers={"HX-Request": "true"})
    assert r.headers.get("HX-Refresh") == "true" and "New since your last visit" not in client.get("/jobs").text
    jsonstore.save(scheduled.SEEN, {"ts": now - 7200})
    assert "New since your last visit" in client.get("/jobs").text
    jsonstore.save(scheduled.SEEN, {"ts": now - 1000, "since": now - 7200})  # the next visit, later
    assert "New since your last visit" not in client.get("/jobs").text


def test_limited_job_editor_shows_what_it_may_use(client, app_module, monkeypatch, tmp_path):
    from app import scheduled
    monkeypatch.setattr(scheduled, "JOBS", str(tmp_path / "jobs.json"))
    jid = scheduled.save({"name": "Mail", "prompt": "svc mail demomail list and @demoapi", "kind": "manual",
                          "profile": "standard", "scope": "1"})
    html = client.get(f"/jobs/{jid}").text
    assert "This job may use: <code>demoapi</code>, <code>demomail</code>" in html


def test_network_approval_card_shows_the_process(client, app_module, monkeypatch):
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    rid = activity.create("telemetry.example.com:443", "network", "connect")
    activity.create("telemetry.example.com:443", "network", "connect")
    activity.set_process(rid, {"command": ".venv/bin/python worker.py", "user": "claude", "origin": {"tmux": "claude-rc"}})
    html = client.get("/partials/approvals").text
    assert '<span class="mono">.venv/bin/python worker.py (claude)</span>' in html and "2 connections waiting" in html
    activity.decide(rid, False)


def test_audit_rows_show_the_source(client, app_module):
    from app import auditlog
    auditlog.write("network", "telemetry.example.com:443", "connect", "approved", actor="claude",
                   origin={"tmux": "claude-rc", "session": "5e194a13-8b1b-524e-b29e-bba2b7263ff2"})
    html = client.get("/logs?q=telemetry.example.com").text
    row = html[html.index('data-audit-row'):]
    row = row[:row.index("audit-detail")]
    assert 'class="faint audit-source"' in row and "source%3A" in row and "5e194a13" in row  # tentacontrol's own label
