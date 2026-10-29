"""Claude → Jobs: schedules, the claude command line per profile, reading the answer, when to notify."""
import json
import os
import re
import time

import pytest


@pytest.fixture
def sj(app_module):
    from app import scheduled
    return scheduled


def lt(ts):
    return time.localtime(ts)


def at(y, mo, d, h=0, mi=0):
    return int(time.mktime((y, mo, d, h, mi, 0, 0, 0, -1)))


def test_daily_and_weekly(sj):
    t = sj.next_run({"kind": "daily", "time": "07:00"}, at(2026, 10, 21, 8, 0))
    assert (lt(t).tm_mday, lt(t).tm_hour, lt(t).tm_min) == (22, 7, 0)
    t = sj.next_run({"kind": "daily", "time": "07:00"}, at(2026, 10, 21, 6, 59))
    assert (lt(t).tm_mday, lt(t).tm_hour) == (21, 7)
    t = sj.next_run({"kind": "weekly", "day": 0, "time": "07:00"}, at(2026, 10, 21, 8, 0))  # 21 Oct 2026 is a Wednesday
    assert lt(t).tm_wday == 0 and lt(t).tm_mday == 26


def test_hourly_and_every(sj):
    t = sj.next_run({"kind": "hourly", "minute": 15}, at(2026, 10, 21, 8, 20))
    assert (lt(t).tm_hour, lt(t).tm_min) == (9, 15)
    now = at(2026, 10, 21, 8, 0)
    assert sj.next_run({"kind": "every", "hours": 6}, now, now) == now + 6 * 3600
    assert sj.next_run({"kind": "every", "hours": 6}, now) == now + 60  # never ran: right away


@pytest.mark.parametrize("expr,after,expect", [
    ("0 7 * * 1-5", at(2026, 10, 23, 8), (26, 7, 0)),      # Fri after 07:00 → Mon
    ("*/15 * * * *", at(2026, 10, 21, 8, 1), (21, 8, 15)),
    ("30 2 1 * *", at(2026, 10, 21), (1, 2, 30)),          # first of next month
    ("0 9 * * 0", at(2026, 10, 21), (25, 9, 0)),           # Sunday
    ("0 9 * * 7", at(2026, 10, 21), (25, 9, 0)),           # 7 = Sunday too
])
def test_cron(sj, expr, after, expect):
    t = sj.next_run({"kind": "cron", "expr": expr}, after)
    assert (lt(t).tm_mday, lt(t).tm_hour, lt(t).tm_min) == expect


@pytest.mark.parametrize("form,msg", [
    ({"kind": "cron", "expr": "0 7 * *"}, "five fields"), ({"kind": "cron", "expr": "61 7 * * *"}, "out of range"),
    ({"kind": "daily", "time": "25:00"}, "HH:MM"), ({"kind": "every", "hours": "0"}, "1–168"), ({"kind": "x"}, "unknown"),
])
def test_bad_schedules(sj, form, msg):
    with pytest.raises(ValueError, match=msg):
        sj.clean_schedule(form)


def test_describe(sj):
    assert sj.describe({"kind": "weekly", "day": 0, "time": "07:00"}) == "every Mon at 07:00"
    assert sj.describe({"kind": "every", "hours": 6}) == "every 6 h"


def test_read_only_profile_is_locked_down(sj):
    argv = sj.claude_argv({"name": "x", "prompt": "check disks", "profile": "read-only"}, "run1", "sid")
    assert argv[:3] == ["claude", "-p", "check disks"]  # prompt before the multi-value tool options
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    allowed = argv[argv.index("--allowedTools") + 1]
    assert "Bash(svc:*)" in allowed and "Edit" not in allowed and "Write" not in allowed
    assert "Edit" in argv[argv.index("--disallowedTools") + 1]
    assert json.loads(argv[argv.index("--json-schema") + 1])["properties"]["status"]["enum"] == ["ok", "warn", "alert"]


def test_standard_profile(sj):
    argv = sj.claude_argv({"name": "x", "prompt": "p", "profile": "standard", "model": "haiku"}, "run1", "sid")
    assert argv[argv.index("--permission-mode") + 1] == "bypassPermissions" and "--allowedTools" not in argv
    assert argv[argv.index("--model") + 1] == "haiku"


def test_parse_output(sj):
    ok = json.dumps({"type": "result", "subtype": "success", "is_error": False, "total_cost_usd": 0.01, "num_turns": 3,
                     "permission_denials": [{}], "structured_output": {"status": "warn", "title": "t", "summary": "s"}})
    st, f = sj.parse_output("noise\n" + ok)
    assert st == "done" and f["result"]["status"] == "warn" and f["denials"] == 1 and f["cost"] == 0.01
    err = json.dumps({"type": "result", "subtype": "error_max_turns", "is_error": True, "result": "too long"})
    assert sj.parse_output(err)[0] == "failed"
    assert sj.parse_output("Error: not logged in")[0] == "failed"
    plain = json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": "just text"})
    st, f = sj.parse_output(plain)
    assert st == "done" and f["result"]["status"] == "warn"  # no traffic light → better look at it


@pytest.mark.parametrize("rule,status,light,expect", [
    ("findings", "done", "ok", False), ("findings", "done", "warn", True), ("findings", "done", "alert", True),
    ("always", "done", "ok", True), ("failure", "done", "alert", False), ("failure", "failed", None, True),
    ("findings", "timeout", None, True), ("always", "canceled", None, False),
])
def test_should_notify(sj, rule, status, light, expect):
    assert sj.should_notify({"notify": rule}, {"status": status, "result": {"status": light}}) is expect


def test_save_due_and_catch_up(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    jid = sj.save({"name": "Disk space", "prompt": "df", "kind": "daily", "time": "07:00"})
    assert jid == "disk-space" and sj.get(jid)["profile"] == "read-only" and sj.get(jid)["notify"] == "findings"
    assert sj.save({"name": "Disk space", "prompt": "df", "kind": "daily", "time": "07:00"}) == "disk-space-2"
    jobs = sj.load()
    jobs[jid]["next"] = time.time() - 60
    jobs["disk-space-2"]["next"] = time.time() - 7 * 3600  # missed while tentaclAI was down for too long
    from app import jsonstore
    jsonstore.save(sj.JOBS, jobs)
    got = dict(sj.due())
    assert got[jid] == "schedule" and got["disk-space-2"].startswith("skipped")
    assert sj.due() == []  # moved on
    with pytest.raises(ValueError, match="profile"):
        sj.save({"name": "x", "prompt": "p", "kind": "daily", "time": "07:00", "profile": "root"})


def test_new_events_follow_approval_routing(app_module, tmp_path, monkeypatch):
    from app import notify
    cfg = tmp_path / "notify.json"
    cfg.write_text(json.dumps({"channels": [{"id": "phone"}], "routes": {"approval": ["phone"], "update": []}}))
    monkeypatch.setattr(notify, "CONFIG", str(cfg))
    r = notify.load()["routes"]
    assert r["job_result"] == ["phone"] and r["job_failed"] == ["phone"] and r["update"] == []  # a set choice stays


def test_clone_starts_paused(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    jid = sj.save({"name": "Disk space", "prompt": "df", "kind": "daily", "time": "07:00", "profile": "standard"})
    c = sj.clone(jid)
    assert c == "disk-space-copy" and sj.clone(jid) == "disk-space-copy-2"
    j = sj.get(c)
    assert j["name"] == "Disk space (copy)" and j["enabled"] is False and j["profile"] == "standard" and j["prompt"] == "df"
    assert sj.get(jid)["enabled"] is True


KNOWN = {"mailrelay": {"kind": "service", "parts": {"smtp": "write"}, "enabled": True, "description": "relay"},
         "imap_x": {"kind": "service", "parts": {"imap": "read"}, "enabled": True, "description": ""},
         "slowmail": {"kind": "service", "parts": {"smtp": "confirm"}, "enabled": True, "description": ""},
         "n8n": {"kind": "service", "parts": {"api": "write", "mcp": "confirm"}, "enabled": False, "description": ""},
         "ha": {"kind": "service", "parts": {"mcp": "confirm"}, "enabled": True, "description": ""},
         "nas": {"kind": "ssh", "parts": {"ssh": "write"}, "enabled": True, "description": "SSH host nas"}}


def test_mentions(sj):
    assert sj.mentions("send via @mailrelay, check @imap_x; mail me@example.com and @mailrelay again") == ["mailrelay", "imap_x"]


def test_check_mentions(sj):
    err, warn = sj.check_mentions({"prompt": "use @nope and @n8n", "profile": "standard", "scope": True}, KNOWN)
    assert err == ["@nope is no service or SSH host"]
    assert any("@n8n is disabled" in w for w in warn) and not any("MCP" in w for w in warn)
    _, warn = sj.check_mentions({"prompt": "send with @mailrelay", "profile": "read-only"}, KNOWN)
    assert warn == ["@mailrelay can't send mail in a read-only job"]
    _, warn = sj.check_mentions({"prompt": "send with @slowmail", "profile": "standard"}, KNOWN)
    assert "asks for approval (smtp)" in warn[0]
    err, _ = sj.check_mentions({"prompt": "no names", "profile": "standard", "scope": True}, KNOWN)
    assert "needs at least one @name" in err[0]


def test_context_scope_and_strict_mcp(sj, monkeypatch):
    monkeypatch.setattr(sj, "tentacles", lambda: KNOWN)
    job = {"name": "mail test", "prompt": "send via @mailrelay, check @imap_x", "profile": "standard", "scope": True}
    argv = sj.claude_argv(job, "run1", "sid")
    system = argv[argv.index("--append-system-prompt") + 1]
    assert "@mailrelay = service mailrelay (smtp write) – relay" in system and "svc refuses every other one" in system
    assert "--strict-mcp-config" in argv
    assert "--strict-mcp-config" not in sj.claude_argv(dict(job, scope=False), "run1", "sid")
    ro = sj.claude_argv(dict(job, scope=False, profile="read-only"), "run1", "sid")
    assert "--strict-mcp-config" in ro  # only svc's proxies – they offer a read-only job the reading tools
    assert ro[ro.index("--allowedTools") + 1].endswith(",mcp__ha")
    assert json.loads(ro[ro.index("--mcp-config") + 1]) == {"mcpServers": {"ha": {"type": "stdio", "command": "svc", "args": ["mcp-proxy", "ha"]}}}
    assert json.loads(argv[argv.index("--mcp-config") + 1]) == {"mcpServers": {}}  # limited: none of the named has MCP
    limited = sj.claude_argv(dict(job, prompt="switch @ha and @n8n"), "run1", "sid")
    assert list(json.loads(limited[limited.index("--mcp-config") + 1])["mcpServers"]) == ["ha"]  # n8n is disabled


def test_registry_carries_the_allow_list(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "ACTIVE", str(tmp_path / "runs.json"))
    sj._register("r1", {"name": "a", "profile": "standard", "scope": True, "prompt": "@mailrelay @nas"})
    sj._register("r2", {"name": "b", "profile": "standard", "prompt": "@mailrelay"})
    act = json.load(open(tmp_path / "runs.json"))
    assert act["r1"]["allow"] == ["mailrelay", "nas"] and "allow" not in act["r2"]


def test_state_token_changes(sj, monkeypatch, tmp_path):
    from app import jsonstore
    monkeypatch.setattr(sj, "HISTORY", str(tmp_path / "h.json"))
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "j.json"))
    jsonstore.save(sj.HISTORY, [{"id": "a", "status": "running"}])
    t1 = sj.state_token()
    jsonstore.save(sj.HISTORY, [{"id": "a", "status": "done"}])
    assert sj.state_token() != t1
    monkeypatch.setattr(sj, "SEEN", str(tmp_path / "seen.json"))
    jsonstore.save(sj.HISTORY, [{"id": "a", "status": "queued", "ended": 1}])
    assert sj.unseen() == 0
    jsonstore.save(sj.HISTORY, [{"id": "a", "status": "failed", "ended": 1}])  # same size: the badge's cache still sees it
    assert sj.unseen() == 1


def test_manual_only(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    assert sj.clean_schedule({"kind": "manual", "time": "07:00"}) == {"kind": "manual"}
    assert sj.next_run({"kind": "manual"}, time.time()) is None and sj.describe({"kind": "manual"}) == "manual"
    jid = sj.save({"name": "On demand", "prompt": "p", "kind": "manual"})
    assert sj.get(jid)["next"] is None
    jobs = sj.load(); jobs[jid]["last"] = 0
    from app import jsonstore
    jsonstore.save(sj.JOBS, jobs)
    assert sj.due(time.time() + 10 * 86400) == []  # never due
    sj.set_enabled(jid, True)
    assert sj.get(jid)["next"] is None and sj.get(sj.clone(jid))["next"] is None


def test_steps_from_stream_events(sj):
    tool = {"type": "assistant", "message": {"content": [{"type": "text", "text": "Checking."},
                                                          {"type": "tool_use", "name": "Bash", "input": {"command": "svc list"}}]}}
    res = {"type": "user", "message": {"content": [{"type": "tool_result", "content": [{"type": "text", "text": "a\nb"}], "is_error": False},
                                                     {"type": "tool_result", "content": "denied", "is_error": True}]}}
    assert sj.steps(tool) == [("text", "Checking."), ("tool", "Bash  svc list")]
    assert sj.steps(res) == [("out", "a\nb"), ("err", "denied")]
    assert sj.steps({"type": "system", "subtype": "init"}) == [] and sj.steps({"type": "result"}) == []
    assert sj.steps({"type": "user", "message": {"content": [{"type": "tool_result", "content": "x" * 2000}]}})[0][1].endswith(" …")


def test_parse_output_reads_the_stream_tail(sj):
    stream = "\n".join([json.dumps({"type": "system", "subtype": "init"}), "Warning: something",
                        json.dumps({"type": "result", "subtype": "success", "is_error": False,
                                    "structured_output": {"status": "ok", "title": "t", "summary": "s"}})])
    assert sj.parse_output(stream)[0] == "done"


def test_logs_and_pruning(sj, monkeypatch, tmp_path):
    from app import jsonstore
    monkeypatch.setattr(sj, "LOGS", str(tmp_path))
    jsonstore.save(sj.log_path("run111111"), [{"t": 1, "k": "tool", "s": "Bash svc list"}])
    jsonstore.save(sj.log_path("run222222"), [])
    assert sj.read_log("run111111")[0]["s"] == "Bash svc list" and sj.read_log("../etc") == []
    sj._prune_logs({"run111111"})
    assert sorted(os.listdir(tmp_path)) == ["run111111.json"]


def test_helpers(sj, monkeypatch):
    assert sj.check_helpers("head, grep jq,bash,awk,curl,Bad!") == (["head", "grep", "jq"], ["bash", "awk", "curl", "Bad!"])
    from app import envfile
    monkeypatch.setattr(envfile, "read_env", lambda *a, **k: {})
    assert sj.readonly_helpers() == list(sj.HELPERS_DEFAULT)
    monkeypatch.setattr(envfile, "read_env", lambda *a, **k: {"JOB_READONLY_HELPERS": "head, python3"})
    assert sj.readonly_helpers() == ["head"]  # a refused one is dropped even if it got into .env by hand
    argv = sj.claude_argv({"name": "x", "prompt": "p", "profile": "read-only"}, "r", "s")
    tools = argv[argv.index("--allowedTools") + 1]
    assert "Bash(svc:*)" in tools and "Bash(head:*)" in tools and "python3" not in tools
    assert "these text tools (also in pipes and chains): head" in argv[argv.index("--append-system-prompt") + 1]


def test_definition_roundtrip_and_put(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    monkeypatch.setattr(sj, "tentacles", lambda: KNOWN)
    d = {"name": "Mail test", "prompt": "send via @mailrelay", "schedule": {"kind": "weekly", "day": 1, "time": "07:30"},
         "profile": "standard", "scope": True, "notify": "findings", "max_minutes": 5}
    errors, warnings, summary = sj.put_preview("mail-test", d)
    assert errors == [] and summary.startswith("create (paused) job mail-test: 'Mail test', every Tue at 07:30, standard, only the named tentacles")
    assert sj.put("mail-test", d) == "mail-test" and sj.get("mail-test")["enabled"] is False  # new: paused
    sj.set_enabled("mail-test", True)
    sj.put("mail-test", dict(d, prompt="send via @mailrelay twice"))
    j = sj.get("mail-test")
    assert j["enabled"] is True and j["prompt"] == "send via @mailrelay twice"  # a change keeps the state
    assert sj.definition(j)["schedule"] == {"kind": "weekly", "day": 1, "time": "07:30"}
    assert sj.put_preview("mail-test", d)[2].startswith("change job mail-test")


@pytest.mark.parametrize("jid,d,msg", [
    ("New", {"name": "x", "prompt": "p"}, "job name"), ("new", {"name": "x", "prompt": "p"}, "job name"),
    ("ok", {"name": "x", "prompt": "p", "bogus": 1}, "unknown fields"), ("ok", {"name": "x", "prompt": "p", "schedule": "daily"}, "schedule"),
    ("ok", {"name": "x", "prompt": "p", "profile": "root"}, "profile"), ("ok", ["x"], "JSON object"),
])
def test_put_preview_rejects(sj, monkeypatch, tmp_path, jid, d, msg):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    errors, _, _ = sj.put_preview(jid, d)
    assert errors and msg in errors[0]


@pytest.mark.parametrize("cmd,ok", [
    ("svc mail box move 912 Junk", True), ("svc docker docktopus image prune -a -f", True),
    ("svc ssh nas 'systemctl restart smbd'", True), ("svc mail box move 912 Junk; rm -rf /", False),
    ("svc docker x ps | head", False), ("svc x GET /$(id)", False), ("rm -rf /", False), ("svc config put job x f", False),
    ("svc ssh nas", False), ("svc db pg shell", False), ("svc jobs", False), ("svc 'unbalanced", False), ("", False),
])
def test_check_action(sj, cmd, ok):
    if ok:
        assert sj.check_action(cmd)[0] == "svc"
    else:
        with pytest.raises(ValueError):
            sj.check_action(cmd)


@pytest.mark.parametrize("cmd,reason", [
    ("svc github POST /x -d '" + "a" * 500 + "'", "invalid: longer than 500 characters"),
    ("svc mail box move 1 Junk; rm x", "invalid: contains ;"), ("svc x POST /y -d '{\"a\":\"b\\nc\"}'", "invalid: contains a backslash"),
    ("svc x GET `id`", "invalid: contains `"), ("svc x GET /a\nb", "invalid: contains a line break"),
])
def test_check_action_names_the_reason(sj, cmd, reason):
    with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
        sj.check_action(cmd)


def test_propose_prompt_lists_every_rule_of_check_action(sj):
    # the model must know what check_action refuses – otherwise its proposals end up refused without a reason it knew
    for text in (sj.SYSTEM_PROPOSE, sj.ACTIONS_SCHEMA["items"]["properties"]["command"]["description"]):
        assert "500 characters" in text and "backslash" in text and "`" in text and "one line" in text
        assert all(c in text for c in ";&|$<>") and all(f"svc {r}" in text or f" {r}" in text for r in sj.ACTION_REFUSED)
        assert "balanced quotes" in text and "svc ssh always with a command" in text and "no svc db shell" in text
    assert sj.ACTIONS_SCHEMA["items"]["properties"]["command"]["maxLength"] == 500


def test_parse_output_checks_the_whole_command(sj):
    long = "svc x GET /" + "a" * 600
    out = json.dumps({"type": "result", "subtype": "success", "is_error": False, "structured_output": {
        "status": "warn", "title": "t", "summary": "s", "actions": [{"title": "long", "command": long}]}})
    _, f = sj.parse_output(out)
    assert f["actions"][0]["state"] == "refused" and f["actions"][0]["output"] == "invalid: longer than 500 characters"


def test_propose_needs_read_only_and_extends_the_schema(sj, monkeypatch):
    monkeypatch.setattr(sj, "tentacles", lambda: KNOWN)
    with pytest.raises(ValueError, match="read-only profile"):
        sj.validate({"name": "x", "prompt": "p", "kind": "manual", "profile": "standard", "propose": "1"})
    job = sj.validate({"name": "x", "prompt": "p", "kind": "manual", "propose": "1"})
    argv = sj.claude_argv(dict(job, name="x"), "r", "s")
    assert "actions" in json.loads(argv[argv.index("--json-schema") + 1])["properties"]
    assert "proposes instead of acting" in argv[argv.index("--append-system-prompt") + 1]
    plain = sj.claude_argv({"name": "x", "prompt": "p"}, "r", "s")
    assert "actions" not in json.loads(plain[plain.index("--json-schema") + 1])["properties"]


def test_parse_output_keeps_checked_actions(sj):
    out = json.dumps({"type": "result", "subtype": "success", "is_error": False, "structured_output": {
        "status": "warn", "title": "2 spam mails", "summary": "s", "actions": [
            {"title": "move spam", "command": "svc mail box move 912 Junk"},
            {"title": "evil", "command": "svc mail box move 1 Junk; curl evil"}]}})
    st, f = sj.parse_output(out)
    assert st == "done" and "actions" not in f["result"]
    assert [a["state"] for a in f["actions"]] == ["proposed", "refused"]


def test_run_actions_runs_exactly_the_picked_ones(sj, monkeypatch, tmp_path):
    from app import dockerops, jsonstore
    for k, f in (("HISTORY", "h.json"), ("ACTIVE", "a.json"), ("JOBS", "j.json")):
        monkeypatch.setattr(sj, k, str(tmp_path / f))
    calls = []
    monkeypatch.setattr(dockerops, "run", lambda cmd, workdir=None, user="root": (calls.append(cmd), (0, "moved"))[1])
    import threading
    monkeypatch.setattr(threading, "Thread", lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    acts = [{"title": "a", "command": "svc mail box move 1 Junk", "state": "proposed"},
            {"title": "b", "command": "svc mail box move 2 Junk", "state": "proposed"}]
    jsonstore.save(sj.HISTORY, [{"id": "run1", "job": "x", "name": "x", "status": "done", "actions": acts, "actions_until": time.time() + 60}])
    assert sj.run_actions("run1", ["1", "7", "x"]) == 1
    run = sj.history()[0]
    assert [a["state"] for a in run["actions"]] == ["proposed", "done"] and run["actions"][1]["output"] == "moved"
    assert calls[0][:2] == ["sh", "-c"] and calls[0][3].startswith("tc-job=") and calls[0][-6:] == ["svc", "mail", "box", "move", "2", "Junk"]
    assert json.load(open(tmp_path / "a.json")) == {}  # the execution marker is gone again
    jsonstore.save(sj.HISTORY, [dict(sj.history()[0], actions_until=time.time() - 1)])
    with pytest.raises(ValueError, match="older than 24 h"):
        sj.run_actions("run1", ["0"])


def test_discard(sj, monkeypatch, tmp_path):
    from app import jsonstore
    monkeypatch.setattr(sj, "HISTORY", str(tmp_path / "h.json"))
    acts = [{"title": t, "command": f"svc m move {i} Junk", "state": st} for i, (t, st) in enumerate([("a", "proposed"), ("b", "proposed"), ("c", "done")])]
    jsonstore.save(sj.HISTORY, [{"id": "r1", "job": "x", "status": "done", "actions": acts, "actions_until": time.time() + 60}])
    assert sj.discard_actions("r1", ["0", "2"]) == 1  # a done one stays done
    assert [a["state"] for a in sj.history()[0]["actions"]] == ["discarded", "proposed", "done"]
    assert sj.discard_actions("r1") == 1 and sj.pending_proposals() == 0
    with pytest.raises(ValueError, match="nothing picked"):
        sj.discard_actions("r1")


def test_reach(sj):
    known = dict(KNOWN, slow={"kind": "service", "parts": {"smtp": "confirm"}, "enabled": True, "description": ""})
    assert sj.reach({"profile": "read-only", "prompt": "@mailrelay"}, known) == ([], [])
    w, a = sj.reach({"profile": "standard", "prompt": "x"}, known)
    assert "mailrelay" in w and "nas" in w and "n8n" not in w and "slow" in a and "slowmail" in a  # n8n is disabled
    assert sj.reach({"profile": "standard", "scope": True, "prompt": "@mailrelay and @imap_x"}, known) == (["mailrelay"], [])


def test_rename_follows_into_job_tasks(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    json.dump({"a": {"name": "Mail check", "prompt": "check @mailbox and run svc mail mailbox list; mail me@mailbox.org"},
               "b": {"name": "Other", "prompt": "check @mailbox2 and svc mailbox-x GET /"}}, open(tmp_path / "jobs.json", "w"))
    assert sj.jobs_naming("mailbox") == ["Mail check"]
    assert sj.rename_mentions("mailbox", "inbox") == ["Mail check"]
    jobs = json.load(open(tmp_path / "jobs.json"))
    assert jobs["a"]["prompt"] == "check @inbox and run svc mail inbox list; mail me@mailbox.org"
    assert jobs["b"]["prompt"] == "check @mailbox2 and svc mailbox-x GET /"  # other names that start alike stay
    assert sj.rename_mentions("nothing", "x") == []


def test_overview_flags_names_that_no_longer_exist(sj, monkeypatch, tmp_path):
    monkeypatch.setattr(sj, "JOBS", str(tmp_path / "jobs.json"))
    monkeypatch.setattr(sj, "tentacles", lambda: KNOWN)
    monkeypatch.setattr(sj, "history", lambda: [])
    json.dump({"a": {"name": "A", "prompt": "check @mailrelay and @gone", "schedule": {"kind": "manual"}, "profile": "read-only"}},
              open(tmp_path / "jobs.json", "w"))
    assert sj.overview()[0]["unknown"] == ["gone"]


def test_svc_calls_name_tentacles_too(sj, monkeypatch, tmp_path):
    known = dict(KNOWN, mail_root={"kind": "service", "parts": {"imap": "read"}, "enabled": True, "description": ""})
    prompt = "1. echo x | svc mail mailrelay send --to a@b.c\n2. svc mail mail_root list INBOX; svc ssh nas uptime\n" \
             "3. svc list, svc mail nobody list and svc imap_x GET / – svc info zuerst"
    assert sj.named(prompt, known) == ["mailrelay", "mail_root", "nas", "imap_x"]  # unknown words in svc calls ignored
    assert sj.named("check @nas and svc ssh nas df", known) == ["nas"]
    err, _ = sj.check_mentions({"prompt": "svc mail mail_root list", "profile": "standard", "scope": True}, known)
    assert err == []  # an svc call is enough for a limited job
    monkeypatch.setattr(sj, "ACTIVE", str(tmp_path / "runs.json"))
    monkeypatch.setattr(sj, "tentacles", lambda: known)
    sj._register("r1", {"name": "a", "profile": "standard", "scope": True, "prompt": prompt})
    assert json.load(open(tmp_path / "runs.json"))["r1"]["allow"] == ["mailrelay", "mail_root", "nas", "imap_x"]


def test_improve_asks_for_a_minimal_effective_change(sj):
    rules = sj.SYSTEM_IMPROVE
    for part in ("not longer", "keep the rest word for word", "line numbers", "issue or PR numbers", "workarounds",
                 "\"knowledge\"", "Leave \"prompt\" out when the task worked"):
        assert part in rules, part


def test_prompt_diff_marks_insertions_and_deletions(sj):
    d = sj.prompt_diff("Check the disks.\nReport in German.", "Check the disks of all hosts.\nReport in German.")
    assert ("+", " of all hosts") in d or any(op == "+" and "of all hosts" in t for op, t in d)
    assert not any(op and "German" in t for op, t in d)  # the unchanged line stays unmarked
    assert "".join(t for op, t in d if op != "-") == "Check the disks of all hosts.\nReport in German."
    assert "".join(t for op, t in d if op != "+") == "Check the disks.\nReport in German."
    assert sj.prompt_diff("same", "same") == [("", "same")] and sj.words("a b\nc") == 3
