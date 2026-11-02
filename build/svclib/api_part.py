"""svc <name> <METHOD> <path>: API calls with the credentials injected, OAuth2 client credentials."""
import json
import os
import subprocess
import sys
import time
import hashlib
import re

from . import core, gate, safeguards


# ---------- api ----------

def cmd_call(services, name, method, path, extra):
    svc = gate.get(services, name)
    if not core.enabled(svc):
        sys.exit(f"svc: {name} is disabled")
    api = svc.get("api") or sys.exit(f"svc: {name} has no api part")
    miss = core.missing_vars(api)
    if miss:
        sys.exit(f"svc: {name} not enabled – empty in .env: {', '.join(miss)}")
    bad = curl_args_error(path, extra)
    if bad:
        sys.exit(f"svc: {bad}")
    api = core.render(api)
    url = api["base_url"].rstrip("/") + "/" + path.lstrip("/")
    auth = api.get("auth", {"type": "none"})
    headers = [f"{k}: {v}" for k, v in api.get("headers", {}).items()]
    config = []
    t = auth.get("type", "none")
    if t == "bearer":
        headers.append(f"Authorization: Bearer {auth['token']}")
    elif t == "header":
        headers.append(f"{auth['header']}: {auth['value']}")
    elif t == "basic":
        config.append(f'user = "{auth["user"]}:{auth["password"]}"')
    elif t == "query":
        url += ("&" if "?" in url else "?") + f"{auth['param']}={auth['value']}"
    elif t == "oauth2_client_credentials":
        headers.append(f"Authorization: Bearer {oauth_token(name, auth, api.get('insecure_tls'))}")
    if not any(a.lower().startswith("content-type") for a in extra) and any(a in ("-d", "--data", "--data-raw", "--json") for a in extra):
        headers.append("Content-Type: application/json")
    # secrets (headers, basic auth, URL with query token) go through 0600 files on tmpfs, never into argv
    config.append(f"url = {_q(url)}")
    files = []
    try:
        for content in ("\n".join(headers) + "\n", "\n".join(config) + "\n"):
            files.append(core._shm_file(content))
        # curl runs as tcrun: extra args (-o, -d @file, -K …) only reach what that user may read/write
        cmd = ["curl", "-q", "-sS", "-X", method.upper(), "-H", f"@{files[0]}", "-K", files[1]]
        if api.get("insecure_tls"):
            cmd.append("-k")
        if fail_on_http_error(extra):
            cmd.append("--fail-with-body")
        if method.upper() in ("GET", "HEAD", "OPTIONS"):
            rc = safeguards.scanned("API response", name, "api", f"{method.upper()} {path}", cmd + list(extra), **core.runner())
        else:
            body = " (with body)" if any(a in ("-d", "--data", "--data-raw", "--data-binary", "--json", "-F", "--form", "-T") for a in extra) else ""
            rc = gate.guarded(name, "api", gate.access_mode(svc["api"], "write"), f"{method.upper()} {path}{body}",
                         lambda: subprocess.call(cmd + list(extra), **core.runner()))
        doubled = doubled_prefix(api["base_url"], path)
        if rc and doubled:
            print(f"svc: the path starts with {doubled}, which the base URL already contains – try "
                  f"{path[len(doubled):] or '/'}", file=sys.stderr)
        return rc
    finally:
        for f in files:
            os.unlink(f)


# curl options svc passes on: the request's body, headers, output and timing. Not the method (-X: the write gate
# decides by it), the target (--url, a second URL, --proxy, --connect-to), a config (-K) or what prints the request's
# own headers with the credentials (-v, --trace, --libcurl). Short flags may be bundled (-sS), values attached (-dX).
CURL_FLAGS = {"-i": "--include", "-I": "--head", "-s": "--silent", "-S": "--show-error", "-f": "--fail", "-L": "--location",
              "-G": "--get", "-g": "--globoff", "-N": "--no-buffer", "-0": "--http1.0", "-j": "--junk-session-cookies"}
CURL_LONG_FLAGS = {"--fail-with-body", "--compressed", "--path-as-is", "--http1.1", "--http2", "--no-progress-meter",
                   "--raw", "--fail-early", "--remote-time", "--create-dirs"}
CURL_VALUES = {"-d": "--data", "-F": "--form", "-H": "--header", "-o": "--output", "-w": "--write-out", "-m": "--max-time",
               "-D": "--dump-header", "-b": "--cookie", "-c": "--cookie-jar", "-A": "--user-agent", "-e": "--referer",
               "-T": "--upload-file", "-r": "--range", "-z": "--time-cond", "-Y": "--speed-limit", "-y": "--speed-time"}
CURL_LONG_VALUES = {"--data-raw", "--data-binary", "--data-urlencode", "--json", "--form-string", "--connect-timeout",
                    "--retry", "--retry-delay", "--retry-max-time", "--max-redirs", "--max-filesize", "--limit-rate",
                    "--expect100-timeout"}


def _control_chars(text):
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def curl_args_error(path, extra):
    """why the path or the extra curl arguments are refused – None when they are fine"""
    if _control_chars(path):
        return "the path contains a control character (line break, tab …) – encode it (%0A …)"
    long_flags = set(CURL_FLAGS.values()) | CURL_LONG_FLAGS
    long_values = set(CURL_VALUES.values()) | CURL_LONG_VALUES
    i = 0
    while i < len(extra):
        a = extra[i]
        value = None
        if a in long_values or a in CURL_VALUES:
            if i + 1 >= len(extra):
                return f"{a} needs a value"
            i += 1
            value = extra[i]
        elif a in long_flags:
            pass
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            for j, c in enumerate(a[1:], 1):
                if "-" + c in CURL_VALUES:
                    value = a[j + 1:]
                    if not value:
                        if i + 1 >= len(extra):
                            return f"-{c} needs a value"
                        i += 1
                        value = extra[i]
                    a = "-" + c
                    break
                if "-" + c not in CURL_FLAGS:
                    return f"curl option -{c} is not allowed here (svc sets the method, target and credentials itself)"
        elif a.startswith("-"):
            return (f"curl option {a.split('=')[0]} is not allowed here (svc sets the method, target and credentials itself)"
                    + (" – the value goes in the next argument, without =" if "=" in a else ""))
        else:
            return f"unexpected argument {a[:60]!r} – curl would call it as a second URL; the path is the third argument"
        if value is not None and a in ("-w", "--write-out") and re.search(r"url|json|referer", value, re.I):
            return "-w may not print the URL (it can hold the credentials) – use %{http_code}, %{time_total} …"
        if value is not None and a in ("-H", "--header") and _control_chars(value):
            return "a header contains a control character"
        i += 1
    return None


def fail_on_http_error(extra):
    """exit non-zero on HTTP 4xx/5xx (curl 22, the body is still printed) – unless the caller reads the status itself
    (-w, e.g. svc test) or chose --fail on its own"""
    return not any(a in ("-f", "--fail", "--fail-with-body", "-w", "--write-out") or a.startswith(("-w", "--write-out="))
                   for a in extra)


def doubled_prefix(base_url, path):
    """the base URL's path prefix (e.g. /api) when the request path repeats it – '' otherwise"""
    from urllib.parse import urlparse
    prefix = urlparse(base_url).path.rstrip("/")
    p = "/" + path.lstrip("/")
    return prefix if prefix and (p == prefix or p.startswith(prefix + "/")) else ""


# ---------- oauth2 (client credentials) ----------

def _curl_secret(argv_head, config_lines):
    """run curl (as tcrun) with secrets only in a 0600 config file on tmpfs; return stdout"""
    cfg = core._shm_file("\n".join(config_lines) + "\n")
    try:
        r = subprocess.run(["curl", "-q", "-sS", *argv_head, "-K", cfg], capture_output=True, text=True, **core.runner())
        return r.returncode, r.stdout, r.stderr
    finally:
        os.unlink(cfg)


def _q(v):
    """a quoted value for a curl config file – a line break would start a new option there"""
    if _control_chars(str(v)):
        sys.exit("svc: a value contains a control character (line break, tab …) – encode it (%0A …)")
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def oauth_token(name, auth, insecure=False):
    """client_credentials grant with on-disk cache (0600) until shortly before expiry"""
    key = hashlib.sha256(f"{auth['token_url']}|{auth['client_id']}|{auth.get('scope', '')}".encode()).hexdigest()[:16]
    path = os.path.join(core.OAUTH_CACHE, f"{name}.json")
    try:
        with open(path) as f:
            c = json.load(f)
        if c.get("key") == key and c.get("expires_at", 0) > time.time() + 60:
            return c["access_token"]
    except (OSError, ValueError):
        pass
    cfg = [f"url = {_q(auth['token_url'])}", "request = POST",
           'header = "Content-Type: application/x-www-form-urlencoded"',
           'data-urlencode = "grant_type=client_credentials"']
    if auth.get("scope"):
        cfg.append(f"data-urlencode = {_q('scope=' + auth['scope'])}")
    if auth.get("audience"):
        cfg.append(f"data-urlencode = {_q('audience=' + auth['audience'])}")
    if auth.get("client_auth", "body") == "basic":
        cfg.append(f"user = {_q(auth['client_id'] + ':' + auth['client_secret'])}")
    else:
        cfg.append(f"data-urlencode = {_q('client_id=' + auth['client_id'])}")
        cfg.append(f"data-urlencode = {_q('client_secret=' + auth['client_secret'])}")
    rc, out, err = _curl_secret(["-k"] if insecure else [], cfg)
    try:
        data = json.loads(out)
        token = data["access_token"]
    except (ValueError, KeyError):
        sys.exit(f"svc: {name}: could not get an OAuth token ({(err or out).strip()[:200]})")
    os.makedirs(core.OAUTH_CACHE, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"key": key, "access_token": token, "expires_at": time.time() + int(data.get("expires_in", 3600))}, f)
    return token
