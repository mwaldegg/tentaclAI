"""The admin account (username, email, name, bcrypt password hash in /data/users.json), optional second factor (TOTP),
signed session cookie, login throttling."""
import json
import os
import re
import secrets
import time

import bcrypt
from fastapi import Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import jsonstore, log, totp
from .config import DATA_DIR

USERS_FILE = os.path.join(DATA_DIR, "users.json")  # the accounts – Community has one, the admin
HASH_FILE = os.path.join(DATA_DIR, "admin.hash")  # before accounts: the admin password only (migrated into users.json)
SECRET_FILE = os.path.join(DATA_DIR, "session.secret")
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,31}")
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]+")
PASSWORD_MIN = 10

# one-time setup token, only valid while no password exists (printed to the container log)
SETUP_TOKEN = secrets.token_urlsafe(24)

_failures: dict = {}
_DUMMY_HASH = bcrypt.hashpw(b"no such user", bcrypt.gensalt(rounds=12))  # an unknown name costs as much as a wrong password


def session_secret() -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(SECRET_FILE):
        with open(os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(secrets.token_urlsafe(48))
    with open(SECRET_FILE) as f:
        return f.read().strip()


# ---------------------------------------------------------------- accounts
# data/control/users.json (0600): {"users": [{id, username, email, name, hash, role, created}]}. Community has exactly one
# account (role admin); the list leaves room for more. The session holds the account's id – a renamed user stays signed in.

def users():
    return (jsonstore.load(USERS_FILE) or {}).get("users", [])


def _save(us):
    jsonstore.save(USERS_FILE, {"users": us}, mode=0o600)


def admin():
    us = users()
    return next((u for u in us if u.get("role") == "admin"), us[0] if us else None)


def get_user(username):
    name = (username or "").strip().lower()
    return next((u for u in users() if u.get("username") == name), None) if name else None


def has_account() -> bool:
    a = admin()
    return bool(a and a.get("hash"))


def profile_missing(user=None) -> bool:
    """an account from before usernames (migrated admin.hash): username and email still to be set – the given user's
    (the signed-in one), or the admin's; never for a user of the central server, which has no local account"""
    a = user if user is not None else admin()
    return bool(a) and a.get("source") != "central" and not (a.get("username") and a.get("email"))


def profile_error(username, email, name, uid=None):
    """what is wrong with these profile fields, or None"""
    username = (username or "").strip().lower()
    if not USERNAME_RE.fullmatch(username):
        return "username: 2–32 characters, lower-case letters, digits, . _ - (starting with a letter or digit)"
    other = get_user(username)
    if other and other.get("id") != uid:
        return "this username is taken"
    if len(email or "") > 254 or not EMAIL_RE.fullmatch((email or "").strip()):
        return "a valid email address is needed"
    if len(name or "") > 80:
        return "name: at most 80 characters"
    return None


def password_error(pw, pw2):
    if len(pw) < PASSWORD_MIN:
        return f"password: at least {PASSWORD_MIN} characters"
    if pw != pw2:
        return "passwords do not match"
    return None


def _hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def create_admin(username, email, name, pw):
    u = {"id": secrets.token_hex(6), "username": username.strip().lower(), "email": email.strip(), "name": name.strip(),
         "hash": _hash_pw(pw), "role": "admin", "created": time.time()}
    _save([u])
    return u


def _update(uid, **fields):
    us = users()
    for u in us:
        if u.get("id") == uid:
            u.update(fields)
            _save(us)
            return u
    return None


def update_profile(uid, username, email, name):
    return _update(uid, username=username.strip().lower(), email=email.strip(), name=(name or "").strip())


def set_password(pw: str, uid=None) -> int:
    """the password of this account (default: the admin) – signs every browser out (a new session generation);
    returns it, so the browser that changed it can stay signed in"""
    uid = uid or (admin() or {}).get("id")
    u = next((u for u in users() if u.get("id") == uid), None) or {}
    gen = int(u.get("gen") or 0) + 1
    _update(uid, hash=_hash_pw(pw), gen=gen)
    return gen


def check_password(pw: str, uid=None) -> bool:
    u = next((u for u in users() if u.get("id") == uid), None) if uid else admin()
    try:
        return bool(u) and bcrypt.checkpw(pw.encode(), u.get("hash", "").encode())
    except ValueError:
        return False


def check_login(username, pw):
    """the account for this username + password, or None; while the admin has no username yet (migrated), the
    password alone"""
    a = admin()
    u = a if a and not a.get("username") else get_user(username)
    try:
        ok = bcrypt.checkpw(pw.encode(), u["hash"].encode() if u else _DUMMY_HASH)
    except (ValueError, KeyError):
        ok = False
    return u if ok and u else None


def migrate():
    """admin.hash (only a password) → users.json with an admin whose username and email are set after the next sign-in;
    admin.hash stays as admin.hash.migrated. True when it migrated"""
    if os.path.exists(USERS_FILE) or not os.path.exists(HASH_FILE) or not os.path.getsize(HASH_FILE):
        return False
    with open(HASH_FILE, "rb") as f:
        h = f.read().strip().decode()
    _save([{"id": secrets.token_hex(6), "username": "", "email": "", "name": "", "hash": h, "role": "admin",
            "created": os.path.getmtime(HASH_FILE)}])
    os.replace(HASH_FILE, HASH_FILE + ".migrated")
    return True


def sign_in(request: Request, user) -> None:
    """a session for a local account, or for a user of the central server (central.sso_finish – no local account;
    the session carries the user)"""
    from . import central
    request.session.clear()
    request.session["auth"] = True
    request.session["uid"] = user["id"]
    request.session["gen"] = int(user.get("gen") or 0)
    if is_central_id(user["id"]):
        request.session["central_user"] = user
    elif central.breakglass_open():
        request.session["breakglass"] = True  # signed in while the host opened the local sign-in – it stays valid


def current_user(request: Request):
    """the signed-in account (a session from before accounts: the admin). A user of the central server only while
    sign-ins through the server are allowed; a local account only while local sign-ins are (or it came in through
    the emergency access)"""
    from . import central
    if not request.session.get("auth"):
        return None
    uid = request.session.get("uid")
    if is_central_id(uid):
        u = _central_session(request)
        return u if u and central.sso_enabled() else None
    if not request.session.get("breakglass") and not central.local_sign_in():
        return None
    u = admin() if uid is None else next((u for u in users() if u.get("id") == uid), None)
    if u and int(u.get("gen") or 0) != int(request.session.get("gen") or 0):
        return None  # signed in before the password was changed (or reset on the host)
    return u


def is_central_id(uid) -> bool:
    """a user of the central server (id "c:<sub>") rather than a local account"""
    return isinstance(uid, str) and uid.startswith("c:")


def _central_session(request: Request):
    """the user of the central server this session carries, or None"""
    uid = request.session.get("uid")
    u = request.session.get("central_user") or {}
    return u if is_central_id(uid) and u.get("id") == uid else None


def is_central(request: Request) -> bool:
    return _central_session(request) is not None


def username(request: Request) -> str:
    u = current_user(request)
    return (u or {}).get("username", "")


def throttled(ip: str) -> int:
    """seconds the client still has to wait (exponential backoff after 3 failures)"""
    n, last = _failures.get(ip, (0, 0.0))
    if n < 3:
        return 0
    wait = min(2 ** (n - 3) * 5, 900)
    return max(0, int(last + wait - time.time()))


def register_failure(ip: str) -> None:
    n, _ = _failures.get(ip, (0, 0.0))
    _failures[ip] = (n + 1, time.time())


def clear_failures(ip: str) -> None:
    _failures.pop(ip, None)


def logged_in(request: Request) -> bool:
    return has_account() and current_user(request) is not None


def same_origin(request: Request) -> bool:
    """CSRF guard for state-changing requests and websockets."""
    origin = request.headers.get("origin")
    if not origin:
        return True  # same-origin form posts from old browsers / curl; cookie is SameSite=Strict anyway
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return origin.split("://", 1)[-1] == host


# ---------------------------------------------------------------- second factor (TOTP), optional
# data/control/twofactor.json (0600): secret, last used step, recovery code hashes, trusted browsers.
TWOFACTOR_FILE = os.path.join(DATA_DIR, "twofactor.json")
PENDING_SECONDS = 300           # password → code: 5 minutes
TRUST_DAYS = 30                 # "trust this browser"
TRUST_COOKIE = "tc_trust"
FAIL_DELAY = 1.0                # seconds after a wrong password or code (slows guessing down)
RECOVERY_ROUNDS = 10            # bcrypt cost of the recovery code hashes


def _2fa():
    """the 2FA state – a file that exists but can't be read counts as on, with no secret: no code fits, so the
    sign-in stays closed (not open without the second factor) until ./tentaclai.sh reset-2fa"""
    try:
        with open(TWOFACTOR_FILE) as f:
            s = json.load(f)
        if isinstance(s, dict):
            return s
    except FileNotFoundError:
        return {"enabled": False}
    except (OSError, ValueError):
        pass
    log.get("auth").error(f"{TWOFACTOR_FILE} is unreadable – sign-in needs a second factor that can't be checked; "
                          "./tentaclai.sh reset-2fa switches 2FA off")
    return {"enabled": True, "broken": True}


def _2fa_save(s):
    jsonstore.save(TWOFACTOR_FILE, {k: v for k, v in s.items() if k != "broken"}, mode=0o600)


def _2fa_lock():
    """read-modify-write of twofactor.json one at a time: a TOTP step or recovery code can't be used twice at once"""
    return jsonstore.locked(TWOFACTOR_FILE)


def twofactor_enabled() -> bool:
    return bool(_2fa().get("enabled"))


def twofactor_status():
    s = _2fa()
    return {"enabled": bool(s.get("enabled")), "recovery_left": len(s.get("recovery", [])),
            "trusted": sorted(({"id": k, **v} for k, v in s.get("trusted", {}).items()), key=lambda t: -t.get("last_used", 0))}


def pending_secret():
    """the secret of a running setup (shown as QR code until the first code confirms it)"""
    return _2fa().get("pending_secret", "")


def start_setup():
    """a new secret waiting for its first code (the running setup is replaced)"""
    with _2fa_lock():
        s = _2fa()
        s["pending_secret"] = totp.new_secret()
        _2fa_save(s)
    return s["pending_secret"]


def _hash(code):
    return bcrypt.hashpw(code.strip().lower().encode(), bcrypt.gensalt(rounds=RECOVERY_ROUNDS)).decode()


def confirm_setup(code):
    """turns 2FA on when the code matches the pending secret – returns the recovery codes (shown once) or None"""
    with _2fa_lock():
        s = _2fa()
        secret = s.get("pending_secret")
        counter = totp.verify(secret, code) if secret else None
        if counter is None:
            return None
        codes = totp.new_recovery_codes()
        s.update(enabled=True, secret=secret, last_counter=counter, recovery=[_hash(c) for c in codes], trusted={})
        s.pop("pending_secret", None)
        _2fa_save(s)
    return codes


def check_second_factor(code):
    """'totp', 'recovery' (that code is used up now) or None"""
    with _2fa_lock():
        s = _2fa()
        if not s.get("enabled") or not s.get("secret"):
            return None
        counter = totp.verify(s["secret"], code, s.get("last_counter", -1))
        if counter is not None:
            s["last_counter"] = counter
            _2fa_save(s)
            return "totp"
        given = code.strip().lower()
        for h in s.get("recovery", []):
            if bcrypt.checkpw(given.encode(), h.encode()):
                s["recovery"].remove(h)
                _2fa_save(s)
                return "recovery"
    return None


def new_recovery_codes():
    with _2fa_lock():
        s = _2fa()
        codes = totp.new_recovery_codes()
        s["recovery"] = [_hash(c) for c in codes]
        _2fa_save(s)
    return codes


def disable_twofactor():
    """off – secret, recovery codes and trusted browsers are gone (also: ./tentaclai.sh reset-2fa)"""
    with _2fa_lock():
        _2fa_save({"enabled": False})


def _signer():
    return URLSafeTimedSerializer(session_secret(), salt="tc-trust")


def trust_browser(label):
    """a signed cookie value; its id must also be in twofactor.json, so it can be revoked"""
    tid = secrets.token_urlsafe(12)
    with _2fa_lock():
        s = _2fa()
        s.setdefault("trusted", {})[tid] = {"created": time.time(), "last_used": time.time(), "label": label[:80]}
        _2fa_save(s)
    return _signer().dumps(tid)


def is_trusted(token) -> bool:
    if not token:
        return False
    try:
        tid = _signer().loads(token, max_age=TRUST_DAYS * 86400)
    except BadSignature:  # includes expired
        return False
    with _2fa_lock():
        s = _2fa()
        if tid not in s.get("trusted", {}):
            return False
        s["trusted"][tid]["last_used"] = time.time()
        _2fa_save(s)
    return True


def revoke_trust(tid=None):
    """one trusted browser, or all (tid None)"""
    with _2fa_lock():
        s = _2fa()
        if tid is None:
            s["trusted"] = {}
        else:
            s.get("trusted", {}).pop(tid, None)
        _2fa_save(s)
