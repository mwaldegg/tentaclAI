"""The admin account: setup with username + email, sign-in by username, migration of admin.hash, profile and password
changes, the username in the audit log and on approvals."""
import pytest


@pytest.fixture
def fresh(app_module, tmp_path, monkeypatch):
    """an empty account store (the session-wide test admin stays untouched)"""
    from app import auth
    monkeypatch.setattr(auth, "USERS_FILE", str(tmp_path / "users.json"))
    monkeypatch.setattr(auth, "HASH_FILE", str(tmp_path / "admin.hash"))
    monkeypatch.setattr(auth, "FAIL_DELAY", 0)
    yield auth
    auth.clear_failures("testclient")


def _client(app_module):
    from fastapi.testclient import TestClient
    return TestClient(app_module.app)


def test_profile_rules(fresh):
    auth = fresh
    assert auth.profile_error("mwa", "m@example.org", "") is None
    assert auth.profile_error("MWa", "m@example.org", "Max") is None  # stored lower-case
    for bad in ("", "a", "-x", "with space", "x" * 33, "ümlaut"):
        assert "username" in auth.profile_error(bad, "m@example.org", "")
    assert "email" in auth.profile_error("mwa", "not-an-address", "")
    assert "email" in auth.profile_error("mwa", "", "")
    assert "name" in auth.profile_error("mwa", "m@example.org", "x" * 81)
    assert auth.password_error("short", "short") and auth.password_error("longenough1", "longenough2")
    assert auth.password_error("longenough1", "longenough1") is None


def test_setup_needs_username_and_email(fresh, app_module, monkeypatch, tmp_path):
    from app import scheduled
    monkeypatch.setattr(scheduled, "JOBS", str(tmp_path / "jobs.json"))
    auth, c = fresh, _client(app_module)
    base = {"token": auth.SETUP_TOKEN, "password": "testpass123", "password2": "testpass123"}
    r = c.post("/setup", data={**base, "username": "mwa", "email": ""})
    assert r.status_code == 400 and "email" in r.text and 'value="mwa"' in r.text and not auth.has_account()
    r = c.post("/setup", data={**base, "token": "wrong", "username": "mwa", "email": "m@example.org"})
    assert r.status_code == 400 and not auth.has_account()
    r = c.post("/setup", data={**base, "username": "MWA", "email": "m@example.org"}, follow_redirects=False)
    assert r.status_code == 303 and auth.admin()["username"] == "mwa" and auth.admin()["name"] == ""
    assert "hash" in auth.admin() and "testpass123" not in open(auth.USERS_FILE).read()
    assert c.get("/settings").status_code == 200  # signed in right away
    assert sorted(scheduled.load()) == ["knowledge-cleanup", "learning-review"]  # a new installation gets the built-in jobs
    assert c.post("/setup", data={**base, "username": "evil", "email": "e@example.org"}, follow_redirects=False).headers["location"] == "/login"


def test_sign_in_by_username(fresh, app_module):
    auth = fresh
    auth.create_admin("mwa", "m@example.org", "", "testpass123")
    c = _client(app_module)
    assert 'name="username"' in c.get("/login").text
    assert c.post("/login", data={"username": "MWA ", "password": "testpass123"}, follow_redirects=False).status_code == 303
    assert c.get("/settings").status_code == 200
    for user, pw in (("mwa", "wrong-password"), ("nobody", "testpass123")):
        r = _client(app_module).post("/login", data={"username": user, "password": pw})
        assert r.status_code == 401 and "wrong username or password" in r.text  # the same answer for both
        auth.clear_failures("testclient")


def test_migration_from_admin_hash(fresh, app_module):
    import bcrypt
    auth = fresh
    with open(auth.HASH_FILE, "wb") as f:
        f.write(bcrypt.hashpw(b"oldpassword1", bcrypt.gensalt(rounds=4)))
    assert auth.migrate() and not auth.migrate()
    assert auth.has_account() and auth.profile_missing()
    import os
    assert os.path.exists(auth.HASH_FILE + ".migrated") and not os.path.exists(auth.HASH_FILE)
    c = _client(app_module)
    assert 'name="username"' not in c.get("/login").text  # no username yet: the password alone
    assert c.post("/login", data={"password": "oldpassword1"}, follow_redirects=False).status_code == 303
    r = c.get("/settings", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/account/complete"
    assert c.get("/partials/overview", headers={"HX-Request": "true"}).headers.get("hx-redirect") == "/account/complete"
    assert c.post("/account/complete", data={"username": "mwa", "email": "bad"}).status_code == 400
    r = c.post("/account/complete", data={"username": "mwa", "email": "m@example.org", "name": "Max"}, follow_redirects=False)
    assert r.status_code == 303 and not auth.profile_missing() and auth.admin()["name"] == "Max"
    assert c.get("/settings").status_code == 200
    assert 'name="username"' in _client(app_module).get("/login").text
    assert _client(app_module).post("/login", data={"username": "mwa", "password": "oldpassword1"},
                                    follow_redirects=False).status_code == 303


def test_old_session_stays_signed_in(fresh, app_module):
    """a session cookie from before accounts (auth only, no uid) belongs to the admin – no forced sign-out on update"""
    auth = fresh
    u = auth.create_admin("mwa", "m@example.org", "", "testpass123")

    class Req:
        session = {"auth": True}
    assert auth.current_user(Req())["id"] == u["id"]
    Req.session = {"auth": True, "uid": "gone"}
    assert auth.current_user(Req()) is None


def test_change_profile_and_password(fresh, app_module):
    auth = fresh
    auth.create_admin("mwa", "m@example.org", "", "testpass123")
    c = _client(app_module)
    c.post("/login", data={"username": "mwa", "password": "testpass123"})
    assert 'value="mwa"' in c.get("/account").text
    r = c.post("/account/profile", data={"username": "max", "email": "x@example.org", "name": "", "current": "wrong"})
    assert r.status_code == 400 and auth.admin()["username"] == "mwa"
    r = c.post("/account/profile", data={"username": "max", "email": "x@example.org", "name": "Max", "current": "testpass123"})
    assert r.status_code == 200 and auth.admin()["username"] == "max"
    assert c.get("/settings").status_code == 200  # renamed – still signed in (the session holds the id)
    assert c.post("/account/password", data={"current": "testpass123", "password": "newpass1234", "password2": "x"}).status_code == 400
    assert c.post("/account/password", data={"current": "testpass123", "password": "newpass1234",
                                              "password2": "newpass1234"}).status_code == 200
    assert auth.check_login("max", "newpass1234") and not auth.check_login("max", "testpass123")


def test_approval_names_the_user(client, app_module):
    from app import activity
    rid = activity.create("demo", "api", "POST /things")
    client.post(f"/approvals/{rid}/approve")
    assert activity.APPROVALS[rid]["by"] == "admin"


def test_security_moved_to_account(client):
    r = client.get("/security", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/account"
    html = client.get("/account").text
    assert "<h1>Account</h1>" in html and 'href="/account" class="active"' in html


def test_password_change_signs_other_browsers_out(fresh, app_module):
    """a cookie that leaked stays valid no longer than the password it came with – the browser that changed it stays in"""
    auth = fresh
    auth.create_admin("mwa", "m@example.org", "", "testpass123")
    a, b = _client(app_module), _client(app_module)
    for c in (a, b):
        c.post("/login", data={"username": "mwa", "password": "testpass123"})
        assert c.get("/settings", follow_redirects=False).status_code == 200
    assert a.post("/account/password", data={"current": "testpass123", "password": "newpass1234",
                                              "password2": "newpass1234"}).status_code == 200
    assert a.get("/settings", follow_redirects=False).status_code == 200
    assert b.get("/settings", follow_redirects=False).status_code in (302, 303, 307)
    auth.set_password("other12345")  # ./tentaclai.sh passwd on the host: every browser
    assert a.get("/settings", follow_redirects=False).status_code in (302, 303, 307)
