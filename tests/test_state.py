"""Connector and skill state in tentacontrol: discovery, defaults, toggles and what is written into the sandbox."""
import json
import os

import pytest

import tclib


@pytest.fixture
def applied(app_module, monkeypatch):
    """records what would be written into the sandbox instead of running docker exec"""
    from app import dockerops
    calls = []
    real = dockerops.run

    def run(cmd, workdir=None, user="root"):
        if cmd[:2] == ["python3", "-c"]:
            calls.append(("skills", json.loads(cmd[3]), user))
            return 0, ""
        return real(cmd, workdir, user)

    def sandbox_exec(cmd, stdin=None, timeout=60):
        calls.append(("managed", json.loads(stdin), cmd))
        return 0, ""
    monkeypatch.setattr(dockerops, "run", run)
    monkeypatch.setattr(dockerops, "sandbox_exec", sandbox_exec)
    return calls


def test_connectors_discover_denies_new_ones(applied, app_module):
    from app import connectors
    assert connectors.discover()
    names = {c["name"]: c for c in connectors.listing()}
    assert set(names) == {"claude.ai Google Drive", "claude.ai Claude Docs"}
    assert not any(c["enabled"] for c in names.values())
    kind, managed, cmd = applied[-1]
    assert kind == "managed" and {d["serverName"] for d in managed["deniedMcpServers"]} == set(names)
    assert "chmod 644" in cmd[-1]  # readable for Claude, written by root

    assert connectors.set_enabled("claude.ai Google Drive", True)
    assert [d["serverName"] for d in applied[-1][1]["deniedMcpServers"]] == ["claude.ai Claude Docs"]
    with pytest.raises(ValueError):
        connectors.set_enabled("claude.ai Nope", True)


def test_skills_discover_listing_and_modes(applied, app_module):
    from app import skills
    assert skills.discover()
    rows = {r["name"]: r for r in skills.listing()}
    assert rows["claude-api"]["tokens"] == 1200 and rows["claude-api"]["mode"] == "on"
    assert rows["dataviz"]["mode"] == "off" and rows["dataviz"]["description"] == "Use this skill for charts"
    assert set(tclib.SKILLS_OFF_DEFAULT) <= set(rows)  # defaults are listed although Claude Code doesn't show them

    assert skills.set_mode("claude-api", "user-invocable-only")
    kind, managed, user = applied[-1]
    assert kind == "skills" and user == "claude" and managed["claude-api"] == "user-invocable-only"
    assert skills.set_mode("dataviz", "on") and applied[-1][1]["dataviz"] == "on"
    with pytest.raises(ValueError):
        skills.set_mode("claude-api", "maybe")
    with pytest.raises(ValueError):
        skills.set_mode("never-seen", "off")
    order = [r["mode"] for r in skills.listing()]
    assert order == sorted(order, key=["on", "user-invocable-only", "off"].index)


def test_skills_discover_without_claude(app_module, monkeypatch):
    from app import dockerops, skills
    monkeypatch.setattr(dockerops, "run", lambda *a, **k: (1, "container is not running"))
    assert skills.discover() is False


def test_models_set_and_apply(app_module, monkeypatch):
    from app import dockerops, models
    calls = []
    monkeypatch.setattr(dockerops, "run", lambda cmd, workdir=None, user="root": (calls.append((json.loads(cmd[3]), user)), (0, ""))[1])
    assert models.current() == tclib.MODELS_DEFAULT  # fresh installation: sparing defaults
    assert models.set_values({"main": "custom", "main_custom": "Claude-Opus-5-5", "effort": "high", "subagents": "",
                              "commands": "haiku", "commands_effort": ""})
    applied, user = calls[-1]
    assert user == "claude"
    assert applied == {"main": "claude-opus-5-5", "effort": "high", "subagents": "", "commands": "haiku", "commands_effort": ""}
    assert models.current() == applied
    for bad in ({"main": "custom", "main_custom": "opus; rm -rf /"}, {"effort": "max"}, {"commands_effort": "ultra"}):
        with pytest.raises(ValueError):
            models.set_values(bad)
    assert models.current() == applied  # refused input changes nothing


def test_polling_leaves_no_session_files(app_module, monkeypatch):
    """/usage and /context are asked every few minutes – they must not pile up as sessions in Claude's history"""
    from app import dockerops, skills, usage
    from conftest import fake_run
    cmds = []
    monkeypatch.setattr(dockerops, "run", lambda cmd, workdir=None, user="root": (cmds.append(cmd), fake_run(cmd))[1])
    usage.refresh_plan()
    skills.discover()
    claude = [c for c in cmds if "claude" in c and "-p" in c]
    assert len(claude) == 2 and all("--no-session-persistence" in c for c in claude)


def test_discover_claude_runs_connectors_and_skills(app_module, monkeypatch):
    import asyncio
    from app import connectors, skills
    ran = []
    monkeypatch.setattr(connectors, "discover", lambda: ran.append("connectors"))
    monkeypatch.setattr(skills, "discover", lambda: ran.append("skills"))
    asyncio.run(app_module.discover_claude())
    assert ran == ["connectors", "skills"]


def test_required_skills_refuse_off(applied, app_module):
    from app import skills
    with pytest.raises(ValueError, match="required"):
        skills.set_mode("inventory", "off")
    assert skills.set_mode("onboard", "user-invocable-only")
    rows = {r["name"]: r for r in skills.listing()}
    assert rows["inventory"]["required"] and rows["onboard"]["mode"] == "user-invocable-only"
    assert skills.set_mode("onboard", "on")


def test_test_path_helpers(app_module):
    from app import services_store
    assert services_store.template_test_path("demoapi") == "/items?limit=1"
    assert services_store.template_test_path("nope") == "" and services_store.template_test_path("../x") == ""
    for bad in ("", "items", "/a b", "/x'", '/x"'):
        assert not services_store.valid_test_path(bad)
    assert services_store.valid_test_path("/environments")


def test_service_rename(app_module):
    from app import services_store as s
    s.save_raw("renme", json.dumps({"api": {"base_url": "https://x"}, "examples": ["svc renme GET /a", "svc db renme tables", "svc renmex GET /"],
                                    "notes": ["use svc renme carefully"]}))
    try:
        data = s.rename("renme", "renamed")
        assert data["examples"] == ["svc renamed GET /a", "svc db renamed tables", "svc renmex GET /"]  # other names untouched
        assert data["notes"] == ["use svc renamed carefully"]
        assert json.loads(s.read_raw("renamed"))["name"] == "renamed"
        with pytest.raises(FileNotFoundError):
            s.read_raw("renme")
        for bad in ("Renamed", "a b", "../x", "", "renamed", "demoapi"):
            with pytest.raises(ValueError):
                s.rename("renamed", bad)
    finally:
        for n in ("renme", "renamed"):
            try:
                s.delete(n)
            except (FileNotFoundError, ValueError):
                pass


def test_second_service_from_a_template_gets_own_variables(app_module):
    from app import services_store as s
    names = ("tok1", "tok2", "tok-three", "tokrepo")
    try:
        assert s.create("tok1", "tokapi") == "a key and a secret (TOKAPI_KEY, TOKAPI_SECRET)"
        assert s.create("tok2", "tokapi") == "a key and a secret (TOK2_KEY, TOK2_SECRET)"  # the hint names its own variables
        s.create("tok-three", "tokapi")
        s.create("tokrepo", "tokgit")
        auth = lambda n: json.loads(s.read_raw(n))["api"]["auth"]
        assert auth("tok1") == {"type": "basic", "user": "${TOKAPI_KEY}", "password": "${TOKAPI_SECRET}"}  # first keeps the names
        assert auth("tok2") == {"type": "basic", "user": "${TOK2_KEY}", "password": "${TOK2_SECRET}"}
        assert auth("tok-three")["user"] == "${TOK_THREE_KEY}"
        assert json.loads(s.read_raw("tokrepo"))["git"]["auth"]["token"] == "${TOKAPI_KEY}"  # other kind: shared on purpose
        assert s.variable_users()["TOKAPI_KEY"] == ["tok1", "tokrepo"]
    finally:
        for n in names:
            try:
                s.delete(n)
            except FileNotFoundError:
                pass


def test_migrate_access_rewrites_service_files(app_module):
    import glob
    import os
    from app import services_store as s
    s.save_raw("acc-new", json.dumps({"git": {"url": "x", "access": "rw"}}))  # saving already writes the new names
    assert json.loads(s.read_raw("acc-new"))["git"]["access"] == "write"
    p = s.path_of("acc-old")
    with open(p, "w") as f:
        json.dump({"name": "acc-old", "db": {"access": "ro"}, "smtp": {"access": "confirm"}}, f)
    try:
        assert "acc-old" in s.migrate_access() and "acc-new" not in s.migrate_access()
        assert json.loads(s.read_raw("acc-old")) == {"name": "acc-old", "db": {"access": "read"}, "smtp": {"access": "confirm"}}
        baks = glob.glob(p + ".bak-*-access")
        assert len(baks) == 1 and json.load(open(baks[0]))["db"]["access"] == "ro"
    finally:
        for f in glob.glob(p + "*") + glob.glob(s.path_of("acc-new") + "*"):
            os.remove(f)


def test_origin_label(app_module, monkeypatch):
    from app import activity, usage
    sid = "369797fa-acf1-46dc-9752-e0a7fdab4d35"
    monkeypatch.setattr(usage, "_local", lambda: {"sessions": {sid: {"title": "Mailcow prüfen"}}})
    assert activity.origin_label({"tmux": "claude-rc", "session": sid}) == "Remote Control · “Mailcow prüfen”"
    assert activity.origin_label({"entry": "cli", "session": "cse_0123456789abcdef"}) == "Claude terminal · cse_0123"
    assert activity.origin_label({}) == "" and activity.origin_label(None) == ""
    assert activity.origin_label({"by": "root"}) == "tentacontrol / host"
    assert activity.clean_origin({"tmux": "<b>x</b>", "token": "secret", "entry": "cli"}) == {"entry": "cli"}


def test_shipped_templates_name_the_service_as_NAME():
    """examples and notes of a template call the service by the placeholder – a fixed name ends up in every copy"""
    import glob
    import re
    root = os.path.join(os.path.dirname(__file__), "..", "services", "_templates")
    call = re.compile(r"\bsvc\s+(?:(?:docker|compose|db|web|files|mail|info|test|git\s+[a-z]+)\s+)?([a-z0-9_-]+)")
    commands = {"docker", "compose", "db", "web", "files", "mail", "info", "test", "git", "ssh", "list", "systems", "audit",
                "pending", "jobs", "config", "sync", "help", "sends"}
    bad = []
    for p in sorted(glob.glob(os.path.join(root, "*.json"))):
        d = json.load(open(p))
        for x in (d.get("examples") or []) + (d.get("notes") or []):
            bad += [f"{os.path.basename(p)}: {x}" for m in call.finditer(str(x)) if m.group(1) not in commands | {"NAME"}]
    assert bad == []


def test_rename_follows_mail_calls(app_module):
    from app import services_store
    services_store.save_raw("mbox", json.dumps({"imap": {"host": "x"}, "examples": ["svc mail mbox list --unseen", "svc mbox GET /"]}))
    try:
        data = services_store.rename("mbox", "mbox_home")
        assert data["examples"] == ["svc mail mbox_home list --unseen", "svc mbox_home GET /"]
    finally:
        for n in ("mbox", "mbox_home"):
            if os.path.exists(services_store.path_of(n)):
                os.remove(services_store.path_of(n))


def test_approvals_survive_a_restart(app_module, monkeypatch):
    """pending requests, their correlation id, a decision not used yet and grants come back after a restart (load);
    a used decision stays used, ids go on counting"""
    import asyncio
    from app import activity
    monkeypatch.setattr(activity, "APPROVALS", {})
    monkeypatch.setattr(activity, "GRANTS", {})
    waiting = activity.create("demohost", "docker", "docker restart x", cid="0123456789ab")
    decided = activity.create("demohost", "docker", "docker restart y", cid="not a cid")
    activity.decide(decided, True, who="admin", grant=True)
    used = activity.create("demohost", "ssh", "reboot")
    activity.decide(used, True)
    activity.use(activity.APPROVALS[used])
    activity.APPROVALS.clear()
    activity.GRANTS.clear()
    activity.load()
    assert activity.APPROVALS[waiting]["status"] == "pending" and activity.APPROVALS[waiting]["cid"] == "0123456789ab"
    assert "cid" not in activity.APPROVALS[decided]
    assert asyncio.run(activity.wait(decided, 1))["status"] == "approved"
    assert asyncio.run(activity.wait(used, 1))["status"] == "error"  # used before the restart – runs nothing
    assert activity.active_grant("demohost", "docker")["by"] == "admin"
    assert int(activity.create("demohost", "docker", "docker restart z")) > int(used)
    assert oct(os.stat(activity.STATE_FILE).st_mode & 0o777) == "0o600"


def test_log_lines_carry_the_request_id(app_module, client):
    import json
    import logging
    from app import log
    rec = logging.LogRecord("tentacontrol.demo", logging.WARNING, "", 0, "something %s", ("broke",), None)
    tok = log.REQUEST_ID.set("abcdef123456")
    try:
        line = json.loads(log.Formatter(as_json=True).format(rec))
        text = log.Formatter().format(rec)
    finally:
        log.REQUEST_ID.reset(tok)
    assert (line["level"], line["logger"], line["msg"], line["request_id"]) == ("warning", "tentacontrol.demo", "something broke", "abcdef123456")
    assert "WARNING demo: something broke [req abcdef123456]" in text
    assert log.request_id("bad id!") != "bad id!" and log.request_id("proxy-1234-abcd") == "proxy-1234-abcd"
    r = client.get("/healthz", headers={"X-Request-ID": "proxy-1234-abcd"})
    assert r.headers["x-request-id"] == "proxy-1234-abcd"


def test_admin_entries_carry_the_request_id(app_module):
    from app import auditlog, log
    tok = log.REQUEST_ID.set("feedbeef0001")
    try:
        auditlog.write("admin", "demo", "test entry", actor="user")
    finally:
        log.REQUEST_ID.reset(tok)
    import tclib
    from app.config import DATA_DIR
    e = [x for x in tclib.audit_read(DATA_DIR, query="cid:feedbeef0001")[0]]
    assert e and e[0]["action"] == "test entry"



def test_migrate_mcp_access_once(app_module):
    """MCP tools ran unchecked before svc gated them – existing MCP parts keep working as write (now logged), once"""
    import glob
    import os
    from app import services_store as s
    old, kept = s.path_of("mcp-old"), s.path_of("mcp-set")
    with open(old, "w") as f:
        json.dump({"name": "mcp-old", "mcp": {"type": "http", "url": "x"}}, f)
    with open(kept, "w") as f:
        json.dump({"name": "mcp-set", "mcp": {"type": "http", "url": "x", "access": "confirm"}}, f)
    try:
        if os.path.exists(s.MCP_MIGRATED):
            os.remove(s.MCP_MIGRATED)
        changed = s.migrate_mcp_access()
        assert "mcp-old" in changed and "mcp-set" not in changed
        assert json.loads(s.read_raw("mcp-old"))["mcp"]["access"] == "write"
        assert json.loads(s.read_raw("mcp-set"))["mcp"]["access"] == "confirm"
        assert len(glob.glob(old + ".bak-*-mcp")) == 1
        with open(old, "w") as f:  # a new MCP part afterwards: not touched – it reads by default
            json.dump({"name": "mcp-old", "mcp": {"type": "http", "url": "x"}}, f)
        assert s.migrate_mcp_access() == [] and "access" not in json.loads(s.read_raw("mcp-old"))["mcp"]
    finally:
        for f in glob.glob(old + "*") + glob.glob(kept + "*"):
            os.remove(f)


def test_mcp_risks_from_svc_reach_the_approval(app_module):
    from app import activity
    assert activity.clean_review(risks=["destructive tool – the server marks it so", "", 3, "x" * 200, "4th"]) == \
        {"risks": ["destructive tool – the server marks it so", "3", "x" * 80]}
    rid = activity.create("demoapi", "mcp", 'wipe {}', review=activity.clean_review(risks=["destructive tool"]))
    try:
        assert activity.APPROVALS[rid]["risks"] == ["destructive tool"]
    finally:
        activity.decide(rid, False)


def test_network_request_names_its_process(app_module, monkeypatch):
    """the gateway's request gets the process svc found (origin-of) and counts the connections waiting for it; the
    audit entry of the decision carries both and the time it was first requested"""
    import time
    from app import activity, auditlog
    monkeypatch.setattr(activity, "APPROVALS", {})
    logged = []
    monkeypatch.setattr(auditlog, "write", lambda *a, **k: logged.append((a, k)))
    rid = activity.create("mobile.events.example.com:443", "network", "connect")
    assert activity.create("mobile.events.example.com:443", "network", "connect") == rid
    activity.set_process(rid, {"command": ".venv/bin/python worker.py\n", "user": "claude",
                               "origin": {"session": "6576389e-0000-4000-8000-000000000001", "tmux": "claude-rc", "x": "y"}})
    a = activity.APPROVALS[rid]
    assert (a["process"], a["process_user"], a["attempts"]) == (".venv/bin/python worker.py", "claude", 2)
    assert a["origin"] == {"session": "6576389e-0000-4000-8000-000000000001", "tmux": "claude-rc"} and a["from"]
    activity.set_process(rid, {})  # nothing found (the process ended): keeps what is there
    assert a["process"].startswith(".venv")
    activity.decide(rid, True, who="admin")
    activity.audit_network(a, "approved")
    (args, kw), = logged
    assert (kw["process"], kw["process_user"], kw["attempts"]) == (".venv/bin/python worker.py", "claude", 2)
    assert kw["origin"]["tmux"] == "claude-rc" and kw["requested"].startswith(time.strftime("%Y-"))
