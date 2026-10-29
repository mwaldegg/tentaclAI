"""services/*.json – same rules as the `svc` CLI in the claude container."""
import glob
import json
import os
import re
import shutil
import time

import tclib

from . import jsonstore
from .central import check_write
from .config import DATA_DIR, SERVICES_DIR, STACK_DIR, is_secret  # noqa: F401  (STACK_DIR re-exported)
from .envfile import read_env, update_env

TEMPLATES_DIR = os.path.join(SERVICES_DIR, "_templates")
OWN_TEMPLATES_DIR = os.path.join(STACK_DIR, "local", "templates")  # imported templates (site data, git-ignored)

NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
PARTS = tclib.PARTS
variables = tclib.variables


def path_of(name):
    if not NAME.match(name):
        raise ValueError("name: lowercase letters, digits, - and _")
    return os.path.join(SERVICES_DIR, f"{name}.json")


def load_all():
    env = read_env()
    errors = {}
    data = tclib.load_services(SERVICES_DIR, errors=errors)
    out = [describe(n, d, env) for n, d in data.items()] + [describe(n, {}, env, e) for n, e in errors.items()]
    return sorted(out, key=lambda x: x["name"])


def describe(name, data, env=None, error=None):
    env = env if env is not None else read_env()
    vars_ = sorted(variables({k: v for k, v in data.items() if k in PARTS}))
    creds = tclib.secret_variables({k: v for k, v in data.items() if k in PARTS})
    missing = [v for v in vars_ if not env.get(v)]
    enabled = data.get("enabled", True) is not False
    if error:
        state, label = "error", "JSON error"
    elif not enabled:
        state, label = "off", "disabled"
    elif missing:
        state, label = "warn", "token missing"
    else:
        state, label = "ok", "active"
    return {
        "name": name, "data": data, "error": error, "enabled": enabled, "system": data.get("system", ""),
        "tls_off": tclib.tls_unverified(data), "tls_parts": [p for p in tclib.TLS_PARTS if isinstance(data.get(p), dict)],
        "description": data.get("description", ""),
        "kinds": [k for k in PARTS if k in data],
        "docker": docker_info(data.get("docker"), env) if data.get("docker") else None,
        "git": git_info(name, data.get("git")) if data.get("git") else None,
        "db": db_info(data.get("db"), env) if data.get("db") else None,
        "web": web_info(data.get("web"), env) if data.get("web") else None,
        "files": files_info(data.get("files")) if data.get("files") else None,
        "mcp": mcp_info(name, data.get("mcp")) if isinstance(data.get("mcp"), dict) else None,
        # URLs contain no secrets -> show them with ${VAR}s resolved
        "base_url": tclib.render((data.get("api") or {}).get("base_url", ""), env, keep_unknown=True),
        "vars": [{"name": v, "set": bool(env.get(v)), "secret": is_secret(v, creds),
                  "value": "" if is_secret(v, creds) else env.get(v, "")} for v in vars_],
        "missing": missing, "state": state, "label": label,
        "mailbox": mail_address(data, env), "can_add_mailbox": is_mailbox(data),
    }


def git_info(name, git):
    path = git.get("path") or f"/workspace/repos/{name}"
    host_path = path.replace("/workspace", os.path.join(STACK_DIR, "workspace"), 1) if path.startswith("/workspace") else None
    cloned = bool(host_path and os.path.isdir(os.path.join(host_path, ".git")))
    author = git.get("author") if isinstance(git.get("author"), dict) else {}
    return {"url": git.get("url", ""), "access": tclib.access(git.get("access")), "branch": git.get("branch", ""),
            "path": path, "cloned": cloned, "auth": (git.get("auth") or {}).get("type", "none"),
            "author": f"{author['name']} <{author['email']}>" if author.get("name") and author.get("email") else ""}


MCP_TOOLS_DIR = os.path.join(DATA_DIR, "mcp-tools")  # written by svc's MCP proxy at each tools/list
MCP_KINDS = ("read", "write", "destructive")


def mcp_info(name, mcp):
    """access, transport and the tools the server listed last (with svc's kind: read, write, destructive)"""
    tools, at = [], 0
    try:
        with open(os.path.join(MCP_TOOLS_DIR, f"{name}.json")) as f:
            doc = json.load(f)
        at = int(doc.get("at") or 0)
        tools = [{"name": str(t["name"])[:200], "kind": t["kind"], "title": str(t.get("title", ""))[:160]}
                 for t in doc.get("tools", []) if isinstance(t, dict) and "name" in t and t.get("kind") in MCP_KINDS]
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return {"access": tclib.access(mcp.get("access")), "type": mcp.get("type", "stdio" if mcp.get("command") else "http"),
            "tools": tools, "at": at, "at_s": time.strftime("%Y-%m-%d %H:%M", time.localtime(at)) if at else "", "counts": {k: sum(1 for t in tools if t["kind"] == k) for k in MCP_KINDS},
            "overrides": any(isinstance(mcp.get(k), list) and mcp.get(k) for k in ("read_tools", "write_tools"))}


def _sub(v, env):
    return tclib.render(str(v or ""), env, keep_unknown=True)


def db_info(d, env):
    """connection target only – user/password stay hidden"""
    engine = "mysql" if (d.get("engine") or "postgres").lower() in ("mysql", "mariadb") else "postgres"
    return {"engine": engine, "access": tclib.access(d.get("access")),
            "target": f"{_sub(d.get('host'), env)}:{_sub(d.get('port'), env) or ('3306' if engine == 'mysql' else '5432')}/{_sub(d.get('database'), env)}"}


def web_info(w, env):
    return {"url": _sub(w.get("base_url"), env), "auth": (w.get("auth") or {}).get("type", "none")}


def files_info(f):
    return {"target": f"{f.get('ssh_host') or '(system SSH host)'}:{f.get('path', '')}", "access": tclib.access(f.get("access")),
            "sudo": bool(f.get("sudo"))}


def docker_info(d, env):
    """docker hosts run over ssh (a missing ssh_host may come from the system – svc test tells)"""
    return {"access": tclib.access(d.get("access")), "stacks_dir": _sub(d.get("stacks_dir"), env), "target": d.get("ssh_host", "")}


PLACEHOLDER_DOMAIN = "example.com"  # {{DOMAIN}} in templates – the user enters the real address, nothing is guessed


def template_path(tid):
    """file of a template id – the shipped ones first, then own (imported) ones"""
    if not NAME.match(tid or ""):
        raise ValueError("invalid template")
    p = os.path.join(TEMPLATES_DIR, f"{tid}.json")
    own = os.path.join(OWN_TEMPLATES_DIR, f"{tid}.json")
    return own if not os.path.exists(p) and os.path.exists(own) else p


def list_templates():
    out = []
    domain = PLACEHOLDER_DOMAIN
    shipped = sorted(glob.glob(os.path.join(TEMPLATES_DIR, "*.json")))
    taken = {os.path.basename(p) for p in shipped}
    own = [p for p in sorted(glob.glob(os.path.join(OWN_TEMPLATES_DIR, "*.json"))) if os.path.basename(p) not in taken]
    for p in shipped + own:
        try:
            with open(p) as f:
                data = json.load(f)
        except ValueError:
            continue
        meta = data.get("_meta", {})
        out.append({"id": os.path.basename(p)[:-5], "title": meta.get("title", os.path.basename(p)[:-5]),
                    "category": meta.get("category", "General"), "description": data.get("description", ""),
                    "setup": meta.get("setup", "").replace("{{DOMAIN}}", domain), "kinds": [k for k in PARTS if k in data],
                    "own": p in own})
    order = ["Docker hosts", "Smart Home", "Automation", "Docker & Infra", "Monitoring", "Network", "Security", "Apps", "Development",
             "Git repos", "Databases", "Web sources", "Files", "General"]
    out.sort(key=lambda t: (order.index(t["category"]) if t["category"] in order else 99, t["title"].lower()))
    return out


def read_raw(name):
    with open(path_of(name)) as f:
        return f.read()


def save_raw(name, text):
    check_write("services", name)
    data = json.loads(text)  # raises ValueError on invalid JSON
    if not isinstance(data, dict):
        raise ValueError("JSON must be an object")
    data["name"] = name
    tclib.migrate_access(data)  # ro/rw are still understood, but only read/write are written
    jsonstore.save(path_of(name), data, mode=0o644, readable=True)


def migrate_access():
    """ro/rw → read/write in every service file (a backup of each changed file stays) – returns the changed names"""
    changed = []
    for p in sorted(glob.glob(os.path.join(SERVICES_DIR, "*.json"))):
        try:
            data = json.load(open(p))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and tclib.migrate_access(data):
            shutil.copy2(p, f"{p}.bak-{time.strftime('%Y-%m-%d')}-access")
            jsonstore.save(p, data, mode=os.stat(p).st_mode & 0o777, readable=True)
            changed.append(os.path.basename(p)[:-5])
    return changed


MCP_MIGRATED = os.path.join(DATA_DIR, "migrated-mcp-access")


def migrate_mcp_access():
    """once: MCP parts without an access mode get "write" – their tools worked unchecked before svc gated them; new
    MCP parts read by default (a backup of each changed file stays) – returns the changed names"""
    if os.path.exists(MCP_MIGRATED):
        return []
    changed = []
    for p in sorted(glob.glob(os.path.join(SERVICES_DIR, "*.json"))):
        if os.path.basename(p).startswith("_"):
            continue
        try:
            data = json.load(open(p))
        except (OSError, ValueError):
            continue
        mcp = data.get("mcp") if isinstance(data, dict) else None
        if isinstance(mcp, dict) and mcp.get("access") in (None, ""):
            mcp["access"] = "write"
            shutil.copy2(p, f"{p}.bak-{time.strftime('%Y-%m-%d')}-mcp")
            jsonstore.save(p, data, mode=os.stat(p).st_mode & 0o777, readable=True)
            changed.append(os.path.basename(p)[:-5])
    with open(MCP_MIGRATED, "w") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M\n"))
    return changed


def variable_users():
    """${VAR} name → services that use it (a token entered for one is used by all of them)"""
    users = {}
    for n, data in tclib.load_services(SERVICES_DIR).items():
        for v in variables({k: x for k, x in data.items() if k in PARTS}):
            users.setdefault(v, []).append(n)
    return users


def _own_variables(data, name):
    """a second service of the same kind (same parts) gets its own variables instead of silently sharing the first one's
    tokens: PATCHMON_TOKEN_KEY → PATCHMON_SKYNET_TOKEN_KEY. Different kinds keep sharing (e.g. GH_TOKEN for api and git).
    Returns the data and the renames (old → new name, for the setup hint)."""
    kinds = {k for k in PARTS if k in data}
    taken = {}
    for other in tclib.load_services(SERVICES_DIR).values():
        same = {k for k in PARTS if k in other} == kinds
        for v in variables({k: x for k, x in other.items() if k in PARTS}):
            taken[v] = taken.get(v, False) or same
    up = name.upper().replace("-", "_")
    text, renames = json.dumps(data, ensure_ascii=False), {}
    for v in sorted(variables({k: x for k, x in data.items() if k in PARTS})):
        if not taken.get(v) or v.startswith(up + "_"):
            continue
        new = f"{up}_{v.split('_', 1)[1] if '_' in v else v}"
        while new in taken:
            new += "_2"
        text = text.replace("${" + v + "}", "${" + new + "}")
        renames[v] = new
    return json.loads(text), renames


MAIL_ADDRESS = tclib.MAIL_ADDRESS
mail_address = tclib.mail_address


def suggest_name(address):
    """root@bitbunker.at → mail-root-bitbunker (same rule as the form's suggestion)"""
    local, _, domain = address.lower().partition("@")
    raw = f"mail-{local}-{domain.split('.')[0]}" if domain else ""
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9_-]", "-", raw)).strip("-")[:41]


def is_mailbox(data):
    """a mail service with a login – only those get 'another mailbox on this server'"""
    return any((data.get(p) or {}).get("user") for p in ("imap", "smtp"))


def _set_address(data, address):
    """put a mailbox address into a mail service: the login (into .env when it is a ${VAR}) and the sender"""
    env, changes = read_env(), {}
    for part in ("imap", "smtp"):
        d = data.get(part)
        if not isinstance(d, dict) or not d.get("user"):
            continue
        m = tclib.VAR.fullmatch(str(d["user"]))
        if m:
            if not env.get(m.group(1)):
                changes[m.group(1)] = address
        else:
            d["user"] = address
    if isinstance(data.get("smtp"), dict) and data["smtp"].get("user"):
        data["smtp"]["from"] = address
    if changes:
        update_env(changes)


def create_like(name, like, address):
    """another mailbox on the same server: host, port, TLS, folders, access and system of `like`, own variables"""
    p = path_of(name)
    if os.path.exists(p):
        raise ValueError(f"{name} already exists")
    address = address.strip()
    if not MAIL_ADDRESS.match(address):
        raise ValueError("mail address: name@domain")
    data = json.loads(read_raw(like))
    if not is_mailbox(data):
        raise ValueError(f"{like} is not a mailbox with a login")
    data = {k: v for k, v in data.items() if k not in ("name", "enabled", "description")}
    old, up = like.upper().replace("-", "_") + "_", name.upper().replace("-", "_") + "_"
    text = json.dumps(data, ensure_ascii=False).replace(f"svc mail {like} ", f"svc mail {name} ")
    for v in sorted(variables({k: x for k, x in data.items() if k in PARTS})):
        new = up + v[len(old):] if v.startswith(old) else up + v
        text = text.replace("${" + v + "}", "${" + new + "}")
    data = json.loads(text)
    _set_address(data, address)
    save_raw(name, json.dumps({"name": name, "description": f"Mailbox {address}", **data}, ensure_ascii=False))


def create(name, template="", address=""):
    """a new service from a template (or the blank one); returns the template's setup hint – shown once, never saved
    as a note: it is about setting the service up, not something Claude needs to read later"""
    p = path_of(name)
    if os.path.exists(p):
        raise ValueError(f"{name} already exists")
    address = address.strip()
    if address and not MAIL_ADDRESS.match(address):
        raise ValueError("mail address: name@domain")
    src = template_path(template) if template else os.path.join(SERVICES_DIR, "_template.json")
    try:
        with open(src) as f:
            tpl = json.load(f)
    except (FileNotFoundError, ValueError):
        tpl = {"description": "", "api": {"base_url": "https://", "auth": {"type": "none"}}}
    setup = str((tpl.get("_meta") or {}).get("setup") or "")
    tpl = {k: v for k, v in tpl.items() if not k.startswith("_")}
    up = name.upper().replace("-", "_")
    domain = address.partition("@")[2].lower() if address else PLACEHOLDER_DOMAIN
    setup = setup.replace("{{DOMAIN}}", domain).replace("svc NAME ", f"svc {name} ").replace("EXAMPLE_", f"{up}_")
    text = json.dumps(tpl, ensure_ascii=False).replace("svc NAME ", f"svc {name} ").replace(" NAME ", f" {name} ").replace("svc docker NAME", f"svc docker {name}").replace("{{DOMAIN}}", domain)
    text = text.replace("EXAMPLE_", f"{up}_").replace('"example"', f'"{name}"')
    data, renames = _own_variables(json.loads(text), name)
    for v, new in renames.items():  # the hint names the variables this service uses, not the first one's
        setup = re.sub(rf"\b{re.escape(v)}\b", new, setup)
    if address and is_mailbox(data):
        _set_address(data, address)
    data = {"name": name, **{k: v for k, v in data.items() if k != "name"}}
    save_raw(name, json.dumps(data, ensure_ascii=False))
    return setup


# ---------------------------------------------------------------- own templates (export a service, import a template)

IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
URL_HOST = re.compile(r"\b[a-z][a-z0-9+.-]*://(?:[^@/\s\"]*@)?([A-Za-z0-9.-]+)")
SITE_ONLY = ("name", "system", "enabled")  # top-level keys that belong to this installation


def _blank(data, path):
    obj = data
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = ""


def _path_label(path):
    return ".".join(str(k) for k in path)


def to_template(name, title="", category="", setup=""):
    """a service as a template like services/_templates/*.json: (template, warnings). Its own variables become EXAMPLE_…,
    `svc <name>` becomes `svc NAME`, the internal domain {{DOMAIN}}; plain values in credential positions are blanked."""
    data = json.loads(read_raw(name))
    data = {k: v for k, v in data.items() if k not in SITE_ONLY and not k.startswith("_")}
    for p in PARTS:
        if isinstance(data.get(p), dict):
            data[p].pop("insecure_tls", None)
    warnings = []
    for path in tclib.literal_secrets(data):
        warnings.append(f"{_path_label(path)}: a plain value in a credential field was left out – use a ${{VAR}}")
        _blank(data, path)
    if isinstance(data.get("notes"), list):
        setup = setup or next((n[7:] for n in data["notes"] if isinstance(n, str) and n.startswith("Setup: ")), "")
        data["notes"] = [n for n in data["notes"] if not (isinstance(n, str) and n.startswith("Setup: "))]
    text = json.dumps(data, ensure_ascii=False)
    up = name.upper().replace("-", "_")
    for v in sorted(variables(data), key=len, reverse=True):
        if v.startswith(up + "_"):
            text = text.replace("${" + v + "}", "${EXAMPLE_" + v[len(up) + 1:] + "}")
    text = (text.replace(f"svc docker {name}", "svc docker NAME").replace(f"svc {name} ", "svc NAME ")
            .replace(f" {name} ", " NAME ").replace(f'"{name}"', '"example"'))
    domain = (read_env().get("TC_DOMAIN") or "").strip().lower()
    if len(domain) > 3 and "." in domain:
        text = re.sub(re.escape(domain), "{{DOMAIN}}", text, flags=re.I)
    data = json.loads(text)
    fixed = sorted({h for h in URL_HOST.findall(text) if "{{DOMAIN}}" not in h and h != "example.com"} | {m.group(0) for m in IPV4.finditer(text)})
    if fixed:
        warnings.append("fixed addresses: " + ", ".join(fixed) + " – fine for a public service, otherwise replace them with {{DOMAIN}}")
    meta = {"title": (title or data.get("description") or name).strip()[:60], "category": (category or "General").strip()[:40]}
    if setup.strip():
        meta["setup"] = setup.strip()
    return {"_meta": meta, **data}, warnings


def check_template(data):
    """refuses what is no usable template – and any plain value in a credential field (it would be a leaked secret)"""
    if not isinstance(data, dict):
        raise ValueError("a template is a JSON object")
    if not isinstance(data.get("_meta"), dict) or not str(data["_meta"].get("title", "")).strip():
        raise ValueError('no "_meta" with a title – not a tentaclAI template')
    if not any(isinstance(data.get(p), dict) for p in PARTS):
        raise ValueError(f"no part ({', '.join(PARTS)})")
    bad = tclib.literal_secrets(data)
    if bad:
        raise ValueError("plain values in credential fields (use ${VAR}): " + ", ".join(_path_label(p) for p in bad))


def save_template(tid, text):
    """an own template into local/templates/<id>.json – ids of shipped templates are refused"""
    tid = (tid or "").strip().lower()
    if not NAME.match(tid):
        raise ValueError("template name: lowercase letters, digits, - and _")
    if os.path.exists(os.path.join(TEMPLATES_DIR, f"{tid}.json")):
        raise ValueError(f"{tid} is a built-in template – pick another name")
    data = json.loads(text)
    check_template(data)
    os.makedirs(OWN_TEMPLATES_DIR, exist_ok=True)
    p = os.path.join(OWN_TEMPLATES_DIR, f"{tid}.json")
    existed = os.path.exists(p)
    if existed:
        shutil.copy2(p, f"{p}.bak-{time.strftime('%Y-%m-%d-%H%M%S')}")
    jsonstore.save(p, data, mode=0o644, readable=True)
    return tid, existed


def set_enabled(name, enabled):
    check_write("services", name)
    data = json.loads(read_raw(name))
    if enabled:
        data.pop("enabled", None)
    else:
        data["enabled"] = False
    save_raw(name, json.dumps(data))


def delete(name):
    check_write("services", name)
    os.remove(path_of(name))


def set_insecure_tls(name, on):
    """switch certificate verification for every TLS part of a service (tclib.TLS_PARTS)"""
    data = json.loads(read_raw(name))
    for part in tclib.TLS_PARTS:
        if isinstance(data.get(part), dict):
            if on:
                data[part]["insecure_tls"] = True
            else:
                data[part].pop("insecure_tls", None)
    save_raw(name, json.dumps(data, ensure_ascii=False))


def valid_test_path(path):
    return bool(path) and path.startswith("/") and len(path) <= 300 and not any(c in path for c in " \n\r'\"")


def template_test_path(name):
    """test_path of the template with the same name (services are usually created from it) – a suggestion"""
    if not NAME.match(name):
        return ""
    try:
        with open(template_path(name)) as f:
            return json.load(f).get("test_path", "")
    except (OSError, ValueError):
        return ""


def set_test_path(name, path):
    """the endpoint `svc test` calls for the api part – one that needs the token, so a wrong token shows up"""
    if not valid_test_path(path):
        raise ValueError("test path: starts with /, no spaces or quotes")
    data = json.loads(read_raw(name))
    data["test_path"] = path
    save_raw(name, json.dumps(data))


def rename(old, new):
    """services/<old>.json → <new>.json; `svc <old> …` calls in examples and notes follow. Returns the service data.
    Tokens (${VAR} in .env) and the system membership stay; git working copies are moved by the caller (sandbox)."""
    if not NAME.match(new or ""):
        raise ValueError("name: lower-case letters, digits, - and _ (max 41)")
    if new == old:
        raise ValueError("that is the current name")
    if os.path.exists(path_of(new)):
        raise ValueError(f"{new} exists already")
    data = json.loads(read_raw(old))
    call = re.compile(r"(\bsvc\s+(?:(?:docker|compose|db|web|files|mail|info|test|git\s+[a-z]+)\s+)?)" + re.escape(old) + r"\b")
    for key in ("examples", "notes"):
        if isinstance(data.get(key), list):
            data[key] = [call.sub(lambda m: m.group(1) + new, x) if isinstance(x, str) else x for x in data[key]]
    save_raw(new, json.dumps(data, ensure_ascii=False))  # new file first – a failure leaves the old one intact
    os.remove(path_of(old))
    return data


def credential_variables():
    """every ${VAR} some service uses as a credential (see tclib.secret_variables) – computed once per request"""
    found = set()
    for data in tclib.load_services(SERVICES_DIR).values():
        found |= tclib.secret_variables(data)
    return found


def secret_check():
    """is_secret for a whole request (settings page, token forms): name hints + credential positions"""
    creds = credential_variables()
    return lambda key: is_secret(key, creds)
