"""Central management, the agent side (control/app/central.py) against a minimal fake server that follows
docs/central.md: enrolling, signed requests, the signed profile (enforced / default items, local items), locks in the
stores and in svc, reverting, audit shipping with its cursor, the config snapshot, leaving and being revoked."""
import base64
import hashlib
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class FakeCentral:
    """the server side of docs/central.md, just enough to test the agent"""
    URL = "https://central.example.test"

    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = b64e(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.tokens, self.agents, self.audit, self.reports, self.configs = {"tok-1"}, {}, {}, [], []
        self.profile, self.rev, self.revoked, self.packages, self.nonces = None, 0, False, {}, set()
        self.runs, self.run_jobs, self.banner = [], [], None

    def code(self, token="tok-1", key=None, **extra):
        from app import central
        return "tce1." + b64e(json.dumps(dict({"url": self.URL, "token": token, "key": key or central.fingerprint(self.pub)}, **extra)).encode())

    def set_profile(self, **p):
        self.rev += 1
        self.profile = dict(p, rev=self.rev)

    def __call__(self, method, url, body, headers):
        path = url[len(self.URL):]
        assert path.startswith("/api/agent/v1/")
        path = path[len("/api/agent/v1"):]
        if path == "/enroll":
            req = json.loads(body)
            if req["token"] not in self.tokens:
                return 403, b'{"error": "token unknown"}'
            self.tokens.discard(req["token"])
            self.agents["A-0001"] = req
            return 200, json.dumps({"agent_id": "A-0001", "central_key": self.pub, "central_name": "Test Central", "profile_rev": self.rev}).encode()
        aid = headers["X-TC-Agent"]
        msg = "\n".join([method, "/api/agent/v1" + path, headers["X-TC-Time"], headers["X-TC-Nonce"],
                         hashlib.sha256(body or b"").hexdigest()]).encode()
        Ed25519PublicKey.from_public_bytes(b64d(self.agents[aid]["public_key"])).verify(b64d(headers["X-TC-Signature"]), msg)
        assert headers["X-TC-Nonce"] not in self.nonces and abs(int(headers["X-TC-Time"]) - time.time()) < 300
        self.nonces.add(headers["X-TC-Nonce"])
        if self.revoked:
            return 410, b'{"error": "revoked"}'
        data = json.loads(body) if body else {}
        if path == "/heartbeat":
            self.status = data
            ask, self.run_jobs = self.run_jobs, []
            return 200, json.dumps({"profile_rev": self.rev, "want_config": False, "run_jobs": ask, "banner": self.banner}).encode()
        if path == "/profile":
            prof = dict(self.profile, agent_id=aid)
            return 200, json.dumps({"profile": prof, "sig": b64e(self.key.sign(canonical(prof)))}).encode()
        if path == "/audit":
            for e in data["entries"]:
                self.audit[e["id"]] = e
            return 200, json.dumps({"stored": len(data["entries"])}).encode()
        if path == "/config":
            self.configs.append(data)
            return 200, b"{}"
        if path == "/report":
            self.reports.append(data)
            return 200, b"{}"
        if path == "/runs":
            self.runs += data["runs"]
            return 200, json.dumps({"stored": len(data["runs"])}).encode()
        if path == "/leave":
            self.agents.pop(aid)
            return 200, b"{}"
        if path.startswith("/packages/"):
            return 200, self.packages[path]
        return 404, b'{"error": "unknown"}'


@pytest.fixture
def fc(app_module, tmp_path, monkeypatch):
    """the agent with its state in tmp_path, talking to a FakeCentral"""
    from app import central, packages
    for name, val in (("DIR", tmp_path / "central"),):
        monkeypatch.setattr(central, name, str(val))
    for name in ("KEY_FILE", "STATE", "PROFILE", "LOCKS", "CA_FILE", "BREAKGLASS"):
        monkeypatch.setattr(central, name, str(tmp_path / "central" / os.path.basename(getattr(central, name))))
    monkeypatch.setattr(packages, "PACKAGES_DIR", str(tmp_path / "packages"))
    monkeypatch.setattr(packages, "PREV_DIR", str(tmp_path / "packages" / ".prev"))
    fake = FakeCentral()
    monkeypatch.setattr(central, "_http", fake)
    yield fake
    central.LOCKS and os.path.exists(central.LOCKS) and os.remove(central.LOCKS)


def test_enroll_and_leave(fc, client):
    from app import central
    with pytest.raises(central.CentralError, match="starts with tce1"):
        central.enroll("hello", "x", [])
    with pytest.raises(central.CentralError, match="doesn't match"):
        central.enroll(fc.code(key="AAAA BBBB CCCC DDDD"), "x", ["services"])
    fc.tokens.add("tok-2")
    st = central.enroll(fc.code("tok-2"), "dev box", ["services", "settings", "nothing"])
    assert st["agent_id"] == "A-0001" and st["areas"] == ["services", "settings"] and central.enrolled()
    assert oct(os.stat(central.KEY_FILE).st_mode & 0o777) == "0o600"
    with pytest.raises(central.CentralError, match="enrolled already"):
        central.enroll(fc.code("tok-1"), "x", [])
    html = client.get("/central").text
    assert "Test Central" in html and "A-0001" in html and "Leave" in html and "connected" in html
    assert "Features (hide" not in html and "(local/CLAUDE.md)" not in html and 'title="hide parts of tentacontrol"' in html  # details as tooltips
    nav = client.get("/settings").text
    assert 'title="Managed by Test Central"' in nav and "dot ok nav-dot" in nav and 'href="/central" class="active' not in nav
    assert 'class="edition ee"' in nav and "★ Enterprise" in nav and 'class="edition cm"' not in nav and "Long arms" not in nav
    central._update(last_error="timed out")
    assert "connection failed" in client.get("/central").text and "dot err nav-dot" in client.get("/settings").text
    central.leave()
    assert not central.enrolled() and "A-0001" not in fc.agents
    html = client.get("/central").text
    assert "Enrollment code" in html and "This installation runs on its own" in html and "nav-locked" in html
    assert 'class="edition cm"' in html and "★ Enterprise" not in html


def test_certificate_from_the_code(fc):
    from app import central
    ca = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    with pytest.raises(central.CentralError, match="not PEM"):
        central.enroll(fc.code(ca="hello"), "x", [])
    central.enroll(fc.code(ca=ca), "box", [])
    assert open(central.CA_FILE).read() == ca + "\n"
    central.leave()
    fc.tokens.add("tok-2")
    central.enroll(fc.code("tok-2", ca=ca), "box", [], ca_pem="-----BEGIN CERTIFICATE-----\nPASTED\n-----END CERTIFICATE-----")
    assert "PASTED" in open(central.CA_FILE).read()  # pasted wins over the code's
    central.leave()


def test_profile_enforced_default_and_locks(fc, client):
    from app import central, services_store
    from app.envfile import read_env, update_env
    update_env({"GIT_USER_NAME": None, "TZ": None})  # the fixture stack is shared by both client variants
    central.enroll(fc.code(), "dev", ["services", "settings", "network"])
    svc = {"description": "Wiki", "web": {"base_url": "https://wiki.example.test"}}
    fc.set_profile(name="Developers", sections={"services": {"cwiki": svc}, "settings": {"GIT_USER_NAME": "Central Bot", "TZ": "Europe/Vienna"},
                                                 "network": {"allow": ["central-allowed.example.test"]}},
                   modes={"services:cwiki": "enforced", "settings:GIT_USER_NAME": "enforced", "settings:TZ": "default",
                          "network:allow:central-allowed.example.test": "enforced"},
                   local_items={"services": False})
    report = central.sync()
    assert {r["id"] for r in report["results"] if r["result"] == "applied"} >= {"services:cwiki", "settings:GIT_USER_NAME", "settings:TZ"}
    assert json.loads(services_store.read_raw("cwiki"))["description"] == "Wiki"
    assert read_env()["GIT_USER_NAME"] == "Central Bot" and read_env()["TZ"] == "Europe/Vienna"
    assert central.locked("services", "cwiki") and central.locked("settings", "GIT_USER_NAME") and not central.locked("settings", "TZ")
    # local changes: an enforced item is refused, a default one may change
    with pytest.raises(ValueError, match="managed by Test Central"):
        services_store.save_raw("cwiki", json.dumps({"description": "mine"}))
    with pytest.raises(ValueError, match="managed by"):
        update_env({"GIT_USER_NAME": "me"})
    update_env({"TZ": "UTC"})
    html = client.get("/settings").text
    assert 'id="f-GIT_USER_NAME" type="text" value="Central Bot" disabled' in html and "central</span>" in html
    assert "central</span>" in client.get("/services").text
    # around tentacontrol (a file edited on the host): reverted at the next sync and reported
    with open(services_store.path_of("cwiki"), "w") as f:
        json.dump({"description": "edited on the host"}, f)
    report = central.sync()
    assert json.loads(services_store.read_raw("cwiki"))["description"] == "Wiki"
    assert {"id": "services:cwiki", "kind": "reverted"} in report["drift"]
    assert {"id": "settings:TZ", "kind": "overridden"} in report["drift"] and read_env()["TZ"] == "UTC"
    assert any(d["kind"] == "local item" for d in report["drift"])  # the fixture's own services, not allowed here
    assert fc.reports and fc.reports[-1]["drift"]
    assert fc.status["profile"]["rev"] == fc.rev and "services" in [s for s in fc.status["areas"]]
    # a new default replaces a value only while it is still the previous profile value
    fc.profile["sections"]["settings"]["TZ"] = "Europe/Berlin"
    fc.set_profile(**{k: v for k, v in fc.profile.items() if k != "rev"})
    central.sync()
    assert read_env()["TZ"] == "UTC"  # changed locally: stays
    from app import auditlog
    actions = [e["action"] for e in auditlog.search("central", rng="1h")[0]]
    assert any("local change reverted: services:cwiki" in a for a in actions) and any("profile applied" in a for a in actions)
    central.leave()
    services_store.save_raw("cwiki", json.dumps({"description": "free again"}))  # no locks after leaving
    from app import egress
    services_store.delete("cwiki")
    egress.remove("allow", "central-allowed.example.test")
    update_env({"GIT_USER_NAME": None, "TZ": None})


def test_refused_areas_and_bad_signature(fc):
    from app import central
    central.enroll(fc.code(), "dev", ["settings"])
    fc.set_profile(name="P", sections={"services": {"x": {"description": "x"}}}, modes={})
    report = central.sync()
    assert report["refused"] == ["services"] and not report["results"]
    fc.set_profile(name="P2", sections={}, modes={})
    real = fc.key
    fc.key = Ed25519PrivateKey.generate()  # a profile signed by someone else
    with pytest.raises(central.CentralError, match="signature"):
        central.sync()
    fc.key = real
    fc.revoked = True
    with pytest.raises(central.CentralError, match="revoked"):
        central.sync()
    assert central.state()["revoked"] and not central.enrolled()
    central.leave()  # works without the server


def test_audit_is_shipped_once(fc):
    from app import auditlog, central
    central.enroll(fc.code(), "dev", [])
    for i in range(3):
        auditlog.write("admin", "testsvc", f"central shipping {i}", actor="system")
    fc.set_profile(name="P", sections={}, modes={})
    central.sync()
    shipped = [e for e in fc.audit.values() if e["action"].startswith("central shipping")]
    assert len(shipped) == 3
    from app import auth
    assert all(e["owner"] == (auth.admin() or {}).get("username", "") and "source" not in e for e in shipped)
    n = len(fc.audit)
    central.sync()
    assert len(fc.audit) - n <= 3  # only the agent's own new entries (profile received …), nothing twice
    assert central.retention_floor() >= 2
    assert fc.configs and "services" in fc.configs[0]["config"]
    cat = {c["key"]: c for c in fc.configs[0]["settings_catalog"]}
    assert cat["TZ"]["label"] == "Time zone" and cat["RC_ENABLED"]["type"] == "bool" and "TC_DIR" not in cat
    before = len(fc.configs)
    central.sync()
    assert len(fc.configs) == before  # the configuration didn't change: not sent again


def test_svc_respects_the_locks(tmp_path):
    import tclib
    d = tmp_path / "control"
    (d / "central").mkdir(parents=True)
    (d / "central" / "locks.json").write_text(json.dumps({"central": "HQ", "enforced": ["services:wiki"]}))
    assert tclib.central_locked(str(d), "services", "wiki") == "HQ"
    assert tclib.central_locked(str(d), "services", "other") == ""
    assert tclib.central_locked(str(tmp_path / "none"), "services", "wiki") == ""


def test_every_writer_respects_the_locks(fc, tmp_path, monkeypatch):
    """systems (also the edit form), an SSH host's sudo, notification channels and rules – not only the import paths"""
    from app import central, jsonstore, notify, sshhosts, systems_store
    monkeypatch.setattr(systems_store, "SYSTEMS_DIR", str(tmp_path / "systems"))
    monkeypatch.setattr(notify, "CONFIG", str(tmp_path / "notify.json"))
    monkeypatch.setattr(notify, "update_env", lambda kv: None)
    jsonstore.save(central.LOCKS, {"enforced": ["systems:edge", "ssh_hosts:gw", "notifications:channel:ops", "notifications:rules"]})
    for call in (lambda: systems_store.create("edge"), lambda: systems_store.save("edge", "d", "", [], []),
                 lambda: sshhosts.set_sudo("gw", "sudo -n"), lambda: notify.remove_channel("ops"),
                 lambda: notify.set_routes({}, {"enabled": False}, 10)):
        with pytest.raises(ValueError, match="managed by"):
            call()
    systems_store.create("other")  # not enforced
    notify.save({"channels": [{"id": "ops", "name": "Ops", "kind": "webhook", "enabled": False}], "routes": {}})
    notify.update_channel("ops", "Ops", True, {})  # on/off and the URL stay local
    with pytest.raises(ValueError, match="managed by"):
        notify.update_channel("ops", "Renamed", True, {})
    cid = notify.add_channel("webhook", "hook", {"url": "https://example.test/h"})
    assert all(cid not in r for r in notify.load()["routes"].values())  # the server sets the routes: no defaults added


def test_module_packages_from_the_profile(fc, ext, monkeypatch):
    """Z4: a profile names a signed package – fetched from the server, checked, installed"""
    import importlib.util
    from app import central, packages
    spec = importlib.util.spec_from_file_location("tp", os.path.join(os.path.dirname(__file__), "test_packages.py"))
    tp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tp)
    priv, pub = tp.new_key()
    monkeypatch.setattr(packages, "PACKAGE_KEYS", [pub])
    data = tp.build("tcx_pkg", priv=priv)
    fc.packages["/packages/tcx_pkg/1.0.0"] = data
    central.enroll(fc.code(), "dev", ["modules"])
    fc.set_profile(name="P", sections={}, modes={},
                   modules={"tcx_pkg": {"mode": "enforced", "package": {"version": "1.0.0", "sha256": hashlib.sha256(data).hexdigest()}}})
    report = central.sync()
    assert any(r["id"] == "modules:tcx_pkg" and r["result"] == "applied" for r in report["results"])
    assert packages.installed_versions() == {"tcx_pkg": "1.0.0"}
    fc.packages["/packages/tcx_pkg/1.1.0"] = tp.build("tcx_pkg", "1.1.0")  # unsigned: refused
    fc.set_profile(name="P", sections={}, modes={}, modules={"tcx_pkg": {"package": {"version": "1.1.0"}}})
    report = central.sync()
    assert any(r["id"] == "modules:tcx_pkg" and r["result"] == "failed" and "not signed" in r["msg"] for r in report["results"])
    assert packages.installed_versions() == {"tcx_pkg": "1.0.0"}
    # the package is managed: not removed, rolled back or replaced here
    with pytest.raises(packages.PackageError, match="managed by"):
        packages.remove("tcx_pkg")
    with pytest.raises(packages.PackageError, match="managed by"):
        packages.rollback("tcx_pkg")
    with pytest.raises(packages.PackageError, match="managed by"):
        packages.install(data)
    assert packages.installed_versions() == {"tcx_pkg": "1.0.0"}


def test_profile_never_switches_a_local_module_on(fc, ext):
    """third-party code (local/extensions, unsigned packages) is switched on by the admin only – the server may switch it off"""
    from app import central, extensions
    ext.install("tcx_local", {"__init__.py": "def register(api):\n    pass\n"})
    ext.install("tcx_builtin", {"__init__.py": "def register(api):\n    pass\n"}, origin="builtin")
    central.enroll(fc.code(), "dev", ["modules"])
    fc.set_profile(name="P", sections={}, modes={}, modules={"tcx_local": {"enabled": True}, "tcx_builtin": {"enabled": True}})
    report = central.sync()
    assert any(r["id"] == "modules:tcx_local" and r["result"] == "failed" and "local module" in r["msg"] for r in report["results"])
    assert "tcx_local" not in extensions.enabled() and "tcx_builtin" in extensions.enabled()
    central.leave()
    extensions.set_enabled("tcx_local", True)  # the admin may
    fc.tokens.add("tok-2")
    central.enroll(fc.code("tok-2"), "dev", ["modules"])
    fc.set_profile(name="P", sections={}, modes={}, modules={"tcx_local": {"enabled": False}})
    central.sync()
    assert "tcx_local" not in extensions.enabled()
    central.leave()


def test_shipped_entries_say_who_and_where(fc, client):
    from app import auditlog, central
    central.enroll(fc.code(), "dev", [])
    auditlog.write("service", "wiki", "GET /pages", actor="claude", origin={"entry": "cli", "session": "0123abcd-0000"})
    central.sync()
    e = next(e for e in fc.audit.values() if e["action"] == "GET /pages")
    assert e["owner"] == "admin" and e["source"].startswith("Claude terminal")
    local = next(x for x in auditlog.search("GET /pages", rng="1h")[0])
    assert "owner" not in local and "source" not in local  # only the copies sent carry them


def test_jobs_from_the_server(fc, monkeypatch):
    from app import central, scheduled
    job = {"name": "Disk check", "prompt": "Check the disks.", "schedule": {"kind": "daily", "time": "07:00"}, "profile": "read-only",
           "notify": "findings"}
    fc.set_profile(name="P", sections={"jobs": {"disk-check": job}}, modes={})
    central.enroll(fc.code(), "dev", ["jobs"])
    central.sync()
    assert scheduled.get("disk-check")["enabled"] is True  # a job from the server runs – an import would be paused
    scheduled.save({"name": "Mine", "prompt": "x", "kind": "manual"}, new_id="mine")
    central.sync()
    assert [j["id"] for j in fc.status["jobs"]] == ["disk-check"] and fc.status["jobs"][0]["enabled"]
    started = []
    monkeypatch.setattr(scheduled, "run_now", lambda jid, trigger="manual": started.append((jid, trigger)) or "r1")
    fc.run_jobs = ["disk-check", "mine"]
    central.sync()
    assert started == [("disk-check", "central")]  # only the server's own jobs
    h = scheduled.history()
    now = time.time()
    h += [{"id": "r1", "job": "disk-check", "name": "Disk check", "trigger": "central", "status": "done", "queued": now - 60,
           "started": now - 50, "ended": now, "seconds": 40, "result": {"status": "warn", "title": "Disk 91 % full", "summary": "sda"}},
          {"id": "r2", "job": "mine", "name": "Mine", "status": "done", "ended": now + 1}]
    scheduled._save_history(h)
    central.sync()
    assert [r["id"] for r in fc.runs] == ["r1"] and fc.runs[0]["result"]["title"] == "Disk 91 % full"
    central.sync()
    assert len(fc.runs) == 1  # not twice
    fc.set_profile(name="P", sections={"jobs": {}}, modes={})
    central.sync()
    assert scheduled.get("disk-check") is None and scheduled.get("mine")  # the server's job goes, the local one stays
    for f in (scheduled.JOBS, scheduled.HISTORY):
        if os.path.exists(f):
            os.remove(f)


def test_hidden_features_and_the_banner(fc, client):
    from app import central
    fc.set_profile(name="P", sections={}, modes={}, features={"hidden": ["jobs", "updates", "terminal", "nonsense"]})
    central.enroll(fc.code(), "dev", [])  # features not allowed yet: nothing hidden, the server is told
    central.sync()
    assert central.hidden_features() == set()
    assert client.get("/jobs").status_code == 200
    central.set_areas(["features"])
    central.sync()
    assert central.hidden_features() == {"jobs", "updates", "terminal"}
    nav = client.get("/settings").text
    assert 'href="/jobs"' not in nav and 'href="/updates"' not in nav and 'href="/network"' in nav
    for path in ("/settings", "/", "/partials/overview"):  # no link leads to a hidden feature, also outside the sidebar
        assert 'href="/terminal' not in client.get(path).text
    r = client.get("/jobs/new")
    assert "turned off by Test Central" in r.text.replace("Turned", "turned")
    assert client.post("/jobs/save", data={"name": "x"}).status_code == 403
    assert "Hidden here" in client.get("/central").text
    # the edition: one answer in the header, on Modules and on Settings → License
    assert "★ Enterprise" in client.get("/modules").text and "managed by <strong>Test Central" in client.get("/license").text
    # the banner: shown on every page until closed, back after a new message
    import uuid
    fc.banner = {"id": uuid.uuid4().hex, "text": "Maintenance tonight 22:00", "level": "warn"}  # the client is shared between runs
    central.sync()
    assert "Maintenance tonight 22:00" in client.get("/settings").text
    client.post("/central/banner/dismiss")
    assert "Maintenance tonight 22:00" not in client.get("/settings").text
    fc.banner = {"id": uuid.uuid4().hex, "text": "Update done", "level": "info"}
    central.sync()
    assert "Update done" in client.get("/settings").text
    fc.banner = None
    central.sync()
    assert central.banner() is None
    central.set_areas([])
    central.sync()
    assert central.hidden_features() == set() and client.get("/jobs").status_code == 200


def test_sign_in_assertions_are_checked(fc, monkeypatch):
    """only a fresh assertion of the server, for this agent and this sign-in, makes a session"""
    from app import central
    monkeypatch.setattr(central, "_control_url", lambda: "https://tc.example.test")
    central.enroll(fc.code(), "box", ["signin"])
    assert central.sso_enabled() and central.local_sign_in()
    url = central.sso_start(session := {})
    assert url.startswith(fc.URL + "/sso/authorize?agent=A-0001&") and "redirect=https%3A%2F%2Ftc.example.test%2Fsso%2Fcallback" in url

    def token(key=None, **over):
        now = int(time.time())
        claims = dict({"v": 1, "aud": "A-0001", "sub": "u1", "username": "dev", "role": "admin", "nonce": session["sso"]["nonce"],
                       "iat": now, "exp": now + 60}, **over)
        raw = canonical(claims)
        return b64e(raw) + "." + b64e((key or fc.key).sign(raw))

    def finish(tok, state=None):
        saved = dict(session["sso"])
        try:
            return central.sso_finish(session, tok, state or saved["state"])
        finally:
            session["sso"] = saved  # the next try reuses the same sign-in
    for bad in (token(key=Ed25519PrivateKey.generate()), token(aud="A-0002"), token(nonce="other"), token(exp=int(time.time()) - 1),
                token(role="root"), token(nonce="é"), token(iat="soon"), "garbage"):
        with pytest.raises(central.CentralError):
            finish(bad)
    with pytest.raises(central.CentralError, match="wasn't started here"):
        finish(token(), state="wrong")
    with pytest.raises(central.CentralError, match="wasn't started here"):
        finish(token(), state="é")  # not a 500
    u = finish(token())
    assert u["id"] == "c:u1" and u["username"] == "dev" and u["source"] == "central"
    tok, st = token(), session.pop("sso")["state"]
    with pytest.raises(central.CentralError):  # used up
        central.sso_finish(session, tok, st)
    # Enterprise only, and the emergency access from the host
    fc.set_profile(sections={}, modes={}, sign_in={"policy": "enterprise"})
    central.sync()
    assert central.sign_in_policy() == "enterprise" and not central.local_sign_in() and not central.breakglass_open()
    central.open_breakglass()
    assert central.local_sign_in() and central.breakglass_open()
    # "all" locks, also without areas_locked, and takes over every part
    fc.set_profile(sections={}, modes={}, areas_all=True)
    central.sync()
    assert central.areas_locked() and central.state()["areas"] == sorted(central.areas())
    with pytest.raises(central.CentralError, match="locks"):
        central.set_areas(["signin"])
    central.leave()
    assert central.sign_in_policy() == "local" and not central.sso_enabled()


def test_a_server_user_has_no_local_account(fc, app_module, monkeypatch):
    """signed in through the server: its own Account page, never asked to complete a local profile"""
    from urllib.parse import parse_qs, urlsplit
    from fastapi.testclient import TestClient
    from app import auth, central
    monkeypatch.setattr(central, "_control_url", lambda: "https://tc.example.test")
    central.enroll(fc.code(), "box", ["signin"])
    c = TestClient(app_module.app, base_url="https://tc.example.test")
    q = parse_qs(urlsplit(c.get("/sso/login", follow_redirects=False).headers["location"]).query)
    now = int(time.time())
    raw = canonical({"v": 1, "aud": "A-0001", "sub": "u1", "username": "dev", "role": "admin", "nonce": q["nonce"][0],
                     "iat": now, "exp": now + 60})
    assert c.post("/sso/finish", data={"assertion": b64e(raw) + "." + b64e(fc.key.sign(raw)), "state": q["state"][0]},
                  follow_redirects=False).status_code == 303
    monkeypatch.setattr(auth, "admin", lambda: {"id": "a1", "hash": "x"})  # the local admin from before usernames
    assert c.get("/", follow_redirects=False).status_code == 200  # not sent to /account/complete
    page = c.get("/account").text
    assert "no local account" in page and "/account/2fa/setup" not in page
    assert auth.profile_missing() and not auth.profile_missing({"source": "central", "username": "dev"})
    central.leave()


def test_enroll_needs_an_agent_id_and_takes_a_null_ca(fc, monkeypatch):
    from app import central
    real = fc.__call__

    def no_id(method, url, body, headers):
        code, out = real(method, url, body, headers)
        d = json.loads(out)
        d.pop("agent_id", None)
        return code, json.dumps(d).encode()
    monkeypatch.setattr(type(fc), "__call__", lambda self, *a: no_id(*a))
    with pytest.raises(central.CentralError, match="no agent id"):
        central.enroll(fc.code(ca=None), "x", [])
    assert not central.enrolled()


def test_profile_package_must_be_the_named_one(fc, ext, monkeypatch):
    import importlib.util
    from app import central, packages
    spec = importlib.util.spec_from_file_location("tp", os.path.join(os.path.dirname(__file__), "test_packages.py"))
    tp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tp)
    priv, pub = tp.new_key()
    monkeypatch.setattr(packages, "PACKAGE_KEYS", [pub])
    fc.packages["/packages/tcx_pkg/1.0.0"] = tp.build("tcx_pkg", "1.0.1", priv=priv)  # another version than asked for
    central.enroll(fc.code(), "dev", ["modules"])
    fc.set_profile(name="P", sections={}, modes={}, modules={"tcx_pkg": {"package": {"version": "1.0.0"}}})
    report = central.sync()
    assert any(r["id"] == "modules:tcx_pkg" and r["result"] == "failed" and "the server sent tcx_pkg 1.0.1" in r["msg"]
               for r in report["results"])
    assert packages.installed_versions() == {}
    central.leave()
