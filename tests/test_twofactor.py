"""Two-factor sign-in (TOTP): the algorithm, recovery codes, trusted browsers and the sign-in flow."""
import base64
import time

import pytest


@pytest.fixture(autouse=True)
def fast(app_module, monkeypatch):
    """no pause after wrong codes, cheap recovery hashes – the real values only slow the tests down"""
    from app import auth
    monkeypatch.setattr(auth, "FAIL_DELAY", 0)
    monkeypatch.setattr(auth, "RECOVERY_ROUNDS", 4)


@pytest.fixture
def tf(app_module):
    """2FA on with a known secret; always off again afterwards (other tests sign in with the password only)"""
    from app import auth, totp
    auth.disable_twofactor()
    auth.start_setup()
    secret = auth.pending_secret()
    codes = auth.confirm_setup(totp.code(secret, int(time.time() // 30)))
    assert codes and auth.twofactor_enabled()
    yield {"secret": secret, "codes": codes}
    auth.disable_twofactor()


def next_code(secret, ahead=1):
    """a valid code not used yet (the setup used the current step)"""
    from app import totp
    return totp.code(secret, int(time.time() // 30) + ahead)


def test_rfc6238_vectors(app_module):
    from app import totp
    s = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code(s, 59 // 30, digits=8) == "94287082"
    assert totp.code(s, 1111111109 // 30, digits=8) == "07081804"
    assert totp.code(s, 59 // 30) == "287082"


def test_window_and_replay(app_module):
    from app import totp
    s = totp.new_secret()
    now = 1_000_000_000
    c = int(now // 30)
    assert totp.verify(s, totp.code(s, c - 1), now=now) == c - 1  # one step late is fine
    assert totp.verify(s, totp.code(s, c + 2), now=now) is None   # too far ahead
    assert totp.verify(s, totp.code(s, c), last_counter=c, now=now) is None  # used already
    assert totp.verify(s, "12 34 5", now=now) is None and totp.verify(s, "", now=now) is None


def test_setup_needs_the_right_code(app_module):
    from app import auth
    auth.disable_twofactor()
    auth.start_setup()
    assert auth.confirm_setup("000000") is None and not auth.twofactor_enabled()
    auth.disable_twofactor()


def test_second_factor_and_recovery(tf):
    from app import auth
    assert auth.check_second_factor(next_code(tf["secret"])) == "totp"
    assert auth.check_second_factor(next_code(tf["secret"])) is None  # replay
    rc = tf["codes"][0]
    assert auth.check_second_factor(rc.upper()) == "recovery"
    assert auth.check_second_factor(rc) is None  # once only
    assert auth.twofactor_status()["recovery_left"] == 9


def test_trusted_browsers(tf):
    from app import auth
    token = auth.trust_browser("Firefox on Linux")
    assert auth.is_trusted(token) and not auth.is_trusted("forged") and not auth.is_trusted("")
    tid = auth.twofactor_status()["trusted"][0]["id"]
    auth.revoke_trust(tid)
    assert not auth.is_trusted(token)
    t2 = auth.trust_browser("Safari on iPhone")
    auth.disable_twofactor()  # switching off forgets every trusted browser
    assert not auth.is_trusted(t2)


def _signin(app_module, password="testpass123"):
    from fastapi.testclient import TestClient
    c = TestClient(app_module.app)
    r = c.post("/login", data={"username": "admin", "password": password}, follow_redirects=False)
    return c, r


def test_signin_flow(tf, app_module):
    from app import auth
    c, r = _signin(app_module)
    assert r.headers["location"] == "/login/2fa"
    assert c.get("/settings", follow_redirects=False).status_code == 303  # not signed in yet
    assert c.post("/login/2fa", data={"code": "000000"}, follow_redirects=False).status_code == 401
    auth.clear_failures("testclient")
    r = c.post("/login/2fa", data={"code": next_code(tf["secret"]), "trust": "1"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert c.get("/settings").status_code == 200
    trust = r.cookies.get(auth.TRUST_COOKIE)
    assert trust and "httponly" in r.headers["set-cookie"].lower()
    # a trusted browser skips the code – but never the password
    c2, r2 = _signin(app_module)
    c3 = type(c2)(app_module.app, cookies={auth.TRUST_COOKIE: trust})
    assert c3.post("/login", data={"username": "admin", "password": "testpass123"}, follow_redirects=False).headers["location"] == "/"
    assert c3.post("/login", data={"username": "admin", "password": "wrong-password"}, follow_redirects=False).status_code == 401
    auth.clear_failures("testclient")


def test_code_page_needs_the_password_first(tf, app_module):
    from fastapi.testclient import TestClient
    c = TestClient(app_module.app)
    assert c.get("/login/2fa", follow_redirects=False).headers["location"] == "/login"
    assert c.post("/login/2fa", data={"code": next_code(tf["secret"])}, follow_redirects=False).headers["location"] == "/login"


def test_signin_with_recovery_code(tf, app_module):
    c, _ = _signin(app_module)
    r = c.post("/login/2fa", data={"code": tf["codes"][1]}, follow_redirects=False)
    assert r.status_code == 303 and c.get("/settings").status_code == 200


def test_security_page_disable_needs_password_and_code(tf, logged_in):
    from app import auth
    assert "Two-factor sign-in" in logged_in.get("/account").text
    assert logged_in.post("/account/2fa/disable", data={"password": "testpass123", "code": "000000"}).status_code == 400
    assert auth.twofactor_enabled()
    r = logged_in.post("/account/2fa/disable", data={"password": "testpass123", "code": next_code(tf["secret"])}, follow_redirects=False)
    assert r.status_code == 303 and not auth.twofactor_enabled()


def test_setup_through_the_page(logged_in, app_module):
    from app import auth, totp
    auth.disable_twofactor()
    logged_in.post("/account/2fa/setup", follow_redirects=False)
    page = logged_in.get("/account").text
    secret = auth.pending_secret()
    assert secret and secret in page and "<svg" in page
    r = logged_in.post("/account/2fa/confirm", data={"code": totp.code(secret, int(time.time() // 30))})
    assert r.status_code == 200 and "Recovery codes" in r.text and auth.twofactor_enabled()
    auth.disable_twofactor()


def test_state_file_is_private(tf, app_module):
    import os
    from app import auth
    assert oct(os.stat(auth.TWOFACTOR_FILE).st_mode & 0o777) == "0o600"


def test_broken_state_file_keeps_the_sign_in_closed(app_module, tf):
    """a twofactor.json that can't be read must not switch the second factor off – no code fits until reset-2fa"""
    from app import auth
    with open(auth.TWOFACTOR_FILE, "w") as f:
        f.write("{not json")
    assert auth.twofactor_enabled()
    assert auth.check_second_factor(next_code(tf["secret"])) is None
    assert auth.check_second_factor(tf["codes"][0]) is None
    with open(auth.TWOFACTOR_FILE, "w") as f:
        f.write("[]")  # valid JSON, wrong shape
    assert auth.twofactor_enabled() and auth.check_second_factor(next_code(tf["secret"])) is None
    auth.disable_twofactor()  # ./tentaclai.sh reset-2fa
    assert not auth.twofactor_enabled() and "broken" not in open(auth.TWOFACTOR_FILE).read()


def test_a_code_counts_once_when_two_requests_race(app_module, tf):
    from concurrent.futures import ThreadPoolExecutor
    from app import auth
    code = next_code(tf["secret"])
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(auth.check_second_factor, [code] * 8))
    assert results.count("totp") == 1
