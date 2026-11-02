"""Extensions: optional Python packages that hook into tentacontrol at start – Extension API v1 (docs/extensions.md).

Where an extension comes from decides what it may do (never what the package claims):
- configured – named in TC_EXTENSIONS (none by default), always loaded; may provide the license
  (provide_license) and replace tentacontrol's own pages and templates.
- builtin    – shipped in the image (BUILTIN_DIR, source control/extensions/), loaded once the admin enabled it.
- signed     – a module package (packages.py) signed by tentaclAI, installed through Modules → Install from file;
  always loaded, the same rights as configured.
- local      – third-party, in STACK_DIR/local/extensions/<name>/ or an unsigned package, loaded once the admin
  enabled it.
builtin, local and package extensions carry an extension.json manifest; the Modules page reads only that, so the code of an
extension that isn't enabled is never imported. Enabling takes effect at tentacontrol's next start, disabling at once
(its pages answer 404, menu entries, tabs, tasks and audit hooks stop).

Registration goes through Api (register(api)); at runtime an extension uses app.extapi – nothing else of app.* is
part of the contract. Without a license provider tentacontrol is tentaclAI Community: edition() "community".
"""
import importlib
import importlib.util
import json
import os
import re
import sys
import traceback

from jinja2 import ChoiceLoader, FileSystemLoader, PrefixLoader

from . import jsonstore
from .central import check_write
from .config import DATA_DIR, STACK_DIR
from .log import get

log = get("extensions")

API_VERSION = 1
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}\Z")
BUILTIN_DIR = os.environ.get("TC_BUILTIN_EXTENSIONS", "/app/extensions")
LOCAL_DIR = os.path.join(STACK_DIR, "local", "extensions")
STATE = os.path.join(DATA_DIR, "extensions.json")
ORIGINS = {"configured": "Enterprise", "signed": "Signed by tentaclAI", "builtin": "Built-in", "local": "Third-party"}
TRUSTED = ("configured", "signed")  # may provide the license and replace tentacontrol's pages
TAB_AREAS = ("settings", "logs", "claude")

LOADED = []      # names of the extensions that registered, in load order
FAILED = {}      # name → why it was not loaded at this start
_exts = {}       # name → {name, origin, title, description, version, author, homepage, path}
_provider = {}   # the license provider: {name, features, edition}
_modules = []    # {key, title, text, nav, licensed, planned, count_url, ext}
_tabs = []       # {area, href, label, icon, ext}
_help = []       # {id, title, template, ext}
_banners = []    # {fn, ext}
_tasks = []      # {fn, every, delay, ext}
_audit_hooks = []  # (fn, ext)
_backup_parts = {}  # section id → {label, export, apply, ext}
_icons = {}      # name → inner SVG
_static = {}     # name → directory served at /x/<name>/static/
_prefix = PrefixLoader({})  # templates of builtin/local extensions: "<name>/file.html"
_pkg_loaded = {}  # package name → the version installed when tentacontrol started (it runs that code until a restart)


class ExtensionError(Exception):
    """an extension broke a rule of the API – it is not loaded"""


# ---------------------------------------------------------------- state: enabled builtin/local extensions

def enabled():
    return set((jsonstore.load(STATE) or {}).get("enabled") or [])


def set_enabled(name, on):
    check_write("modules", name)
    if name not in {e["name"] for e in available()}:
        raise ValueError(f"no extension {name}")
    if origin(name) == "configured":
        raise ValueError(f"{name} is set in TC_EXTENSIONS – change it there")
    if _discover().get(name, {}).get("origin") == "signed":
        raise ValueError(f"{name} is a signed package and always on – remove the package instead")
    names = enabled()
    names = names | {name} if on else names - {name}
    jsonstore.save(STATE, {"enabled": sorted(names)})


def active(name):
    """loaded at this start and (configured or still enabled) – what menu, tabs, pages, tasks and hooks go by"""
    if name not in LOADED:
        return False
    return origin(name) in TRUSTED or name in enabled()


def title(name):
    return (_exts.get(name) or {}).get("title") or name


def origin(name):
    return (_exts.get(name) or {}).get("origin", "")


def restart_pending():
    """enabled extensions that aren't loaded yet (and didn't fail at this start), and packages installed, updated or
    removed since the start – tentacontrol needs a restart. Called on every page: no checksums here."""
    from . import packages
    now = packages.installed_versions()
    out = {n for n in enabled() if n not in LOADED and n not in FAILED and n not in now and n in _discover(packages_too=False)}
    for name, version in now.items():
        if _pkg_loaded.get(name) != version and name not in FAILED and (name in enabled() or packages.is_signed(name)):
            out.add(name)
    out |= {n for n in _pkg_loaded if n not in now and n in LOADED}
    return sorted(out)


# ---------------------------------------------------------------- discovery (manifests only, no import)

def _manifest(path, name, origin_):
    info = {"name": name, "origin": origin_, "path": path, "title": name, "description": "", "version": "", "author": "",
            "homepage": "", "requires_api": None, "error": ""}
    try:
        with open(os.path.join(path, "extension.json")) as f:
            m = json.load(f)
        if not isinstance(m, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as e:
        info["error"] = f"extension.json: {e}"
        return info
    for k in ("title", "description", "version", "author", "homepage"):
        if isinstance(m.get(k), str):
            info[k] = m[k][:300]
    info["requires_api"] = m.get("requires_api")
    if m.get("name") != name:
        info["error"] = f"extension.json names {m.get('name')!r}, the folder is {name!r}"
    elif info["requires_api"] != API_VERSION:
        info["error"] = f"needs Extension API {info['requires_api']}, tentacontrol has {API_VERSION}"
    elif not os.path.isfile(os.path.join(path, "__init__.py")):
        info["error"] = "no __init__.py"
    return info


def _discover(say=False, packages_too=True):
    """builtin, package and local extensions by their manifests – first one wins: builtin, then installed packages
    (checked: signed or not, unchanged), then local/extensions (say: log what is ignored)"""
    from . import packages
    out = {}
    for origin_, base in (("builtin", BUILTIN_DIR), ("package", packages.PACKAGES_DIR), ("local", LOCAL_DIR)):
        if origin_ == "package":
            for name in packages.names() if packages_too else ():
                if name in out:
                    if say:
                        log.warning(f"package {name} ignored – a built-in module has that name")
                    continue
                v = packages.verify_installed(name)
                info = _manifest(v["path"], name, "signed" if v["signed"] else "local")
                info["error"] = v["error"] or info["error"]
                info["package"] = {k: v[k] for k in ("version", "signed", "key")}
                info["package"]["previous"] = packages.previous_version(name)
                out[name] = info
            continue
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for name in names:
            path = os.path.join(base, name)
            if not os.path.isdir(path) or name.startswith((".", "_")) or name == "__pycache__":
                continue
            if name in out:
                if say:
                    log.warning(f"extension {name} in {base} ignored – a built-in one or a package has that name")
                continue
            info = _manifest(path, name, origin_)
            if not NAME_RE.match(name):
                info["error"] = "name: lowercase letters, digits and _ (2–41 characters)"
            out[name] = info
    return out


def available():
    """every extension for the Modules page: configured ones that loaded or failed, builtin and local by manifest"""
    found = _discover()
    out = [dict(e, loaded=e["name"] in LOADED, failed=FAILED.get(e["name"], "")) for e in _exts.values()
           if e["origin"] == "configured"]
    for name, info in found.items():
        out.append(dict(info, loaded=name in LOADED, failed=FAILED.get(name, "") or info["error"]))
    on = enabled()
    for e in out:
        e["enabled"] = e["origin"] in TRUSTED or e["name"] in on
        e.setdefault("package", None)
        e["active"] = active(e["name"])
        e["origin_label"] = ORIGINS[e["origin"]]
    return out


# ---------------------------------------------------------------- the registration API

class Api:
    """what an extension may use in register(api) to hook in"""

    API_VERSION = API_VERSION

    def __init__(self, app, templates, name, origin_):
        self.app, self.templates, self.name, self.origin = app, templates, name, origin_
        self._done = []  # undo steps, run when register() fails half-way

    # pages
    def add_router(self, router):
        """configured/signed: any path (may replace tentacontrol's own pages); others only below /x/<name>/"""
        if self.origin not in TRUSTED:
            base = f"/x/{self.name}"
            bad = [r.path for r in router.routes if not (getattr(r, "path", "") == base or getattr(r, "path", "").startswith(base + "/"))]
            if bad:
                raise ExtensionError(f"routes must start with {base}/ – not {', '.join(bad[:3])}")
        n = len(self.app.router.routes)
        self.app.include_router(router)
        added = self.app.router.routes[n:]
        if self.origin in TRUSTED:  # in front of tentacontrol's own routes, whenever it is loaded
            del self.app.router.routes[n:]
            self.app.router.routes[0:0] = added
        self._done.append(lambda: [self.app.router.routes.remove(r) for r in added if r in self.app.router.routes])

    def add_templates(self, directory):
        """configured/signed: in front of tentacontrol's templates (may replace them); others as "<name>/file.html" """
        env = self.templates.env
        if self.origin in TRUSTED:
            old = env.loader
            env.loader = ChoiceLoader([FileSystemLoader(directory), old])
            self._done.append(lambda: setattr(env, "loader", old))
        else:
            _prefix.mapping[self.name] = FileSystemLoader(directory)
            self._done.append(lambda: _prefix.mapping.pop(self.name, None))
        if env.cache is not None:
            env.cache.clear()

    def add_static(self, directory):
        """files below /x/<name>/static/ (signed-in users only) – ext_static(name, path) in templates"""
        from fastapi.staticfiles import StaticFiles
        if not os.path.isdir(directory):
            raise ExtensionError(f"add_static: {directory} is no directory")
        self.app.mount(f"/x/{self.name}/static", StaticFiles(directory=directory), name=f"x-{self.name}-static")
        route = self.app.router.routes[-1]
        _static[self.name] = directory
        self._done.append(lambda: (self.app.router.routes.remove(route), _static.pop(self.name, None)))

    def add_icon(self, name, svg):
        """an icon for icon(name): the inner SVG of a 24×24 stroke icon (paths, circles …)"""
        if not re.match(r"^[a-z][a-z0-9-]{1,30}\Z", name or ""):
            raise ExtensionError(f"icon name {name!r}: lowercase letters, digits and -")
        if name in _builtin_icons() or name in _icons:
            raise ExtensionError(f"icon {name} exists already")
        _icons[name] = str(svg)
        self._done.append(lambda: _icons.pop(name, None))

    # menu, Modules page, tabs, help
    def add_module(self, key, title, text, nav=None, licensed=False, planned=False, count_url=None):
        """a module for the Modules page; nav = {"href", "label", "icon"} – its sidebar entry, shown while the extension
        is active, the module isn't only planned and – licensed=True – the license unlocks the feature `key`.
        count_url: a page that answers a short text (e.g. a number) for the badge next to the entry."""
        if licensed and self.origin not in TRUSTED:
            raise ExtensionError("licensed modules come from the license provider only")
        if nav and not (isinstance(nav, dict) and nav.get("href") and nav.get("label")):
            raise ExtensionError("nav needs href and label")
        if nav and self.origin not in TRUSTED and not str(nav["href"]).startswith(f"/x/{self.name}"):
            raise ExtensionError(f"nav href must start with /x/{self.name}")
        m = {"key": key, "title": title, "text": text, "nav": nav, "licensed": bool(licensed), "planned": bool(planned),
             "count_url": count_url, "ext": self.name}
        _modules.append(m)
        self._done.append(lambda: _modules.remove(m))

    def add_tab(self, area, href, label, icon="grid"):
        """a tab in the tab bar of Settings, Logs or Claude – the page itself comes with add_router"""
        if area not in TAB_AREAS:
            raise ExtensionError(f"tab area: one of {', '.join(TAB_AREAS)}")
        if self.origin not in TRUSTED and not href.startswith(f"/x/{self.name}"):
            raise ExtensionError(f"tab href must start with /x/{self.name}")
        t = {"area": area, "href": href, "label": label, "icon": icon, "ext": self.name}
        _tabs.append(t)
        self._done.append(lambda: _tabs.remove(t))

    def add_help_section(self, id, title, template):
        """a section at the end of Help – template: one of the extension's templates (rendered without page context)"""
        if not re.match(r"^[a-z][a-z0-9-]{1,40}\Z", id or ""):
            raise ExtensionError(f"help section id {id!r}: lowercase letters, digits and -")
        h = {"id": f"x-{self.name}-{id}" if self.origin not in TRUSTED else id, "title": title, "template": template,
             "ext": self.name}
        _help.append(h)
        self._done.append(lambda: _help.remove(h))

    def add_banner(self, fn):
        """fn(request) → None, or {"text", "kind": info|warn|err, "href", "link"} – a banner at the top of every page.
        Called on every page: keep it cheap."""
        if not callable(fn):
            raise ExtensionError("add_banner needs a function")
        b = {"fn": fn, "ext": self.name}
        _banners.append(b)
        self._done.append(lambda: _banners.remove(b))

    # background work, notifications, audit, backup
    def add_task(self, fn, every, delay=30):
        """fn (sync – run in a thread – or async) every `every` seconds, first after `delay`; skipped while disabled"""
        if not callable(fn) or not isinstance(every, (int, float)) or every < 10:
            raise ExtensionError("add_task needs a function and every >= 10 seconds")
        t = {"fn": fn, "every": every, "delay": delay, "ext": self.name}
        _tasks.append(t)
        self._done.append(lambda: _tasks.remove(t))

    def add_event(self, id, label, priority="normal", description=""):
        """a notification event (Settings → Notifications) – until routed itself it goes where approvals go"""
        from . import notify
        if id in notify.EVENTS:
            raise ExtensionError(f"event {id} exists already")
        if not re.match(r"^[a-z][a-z0-9_]{1,30}\Z", id or "") or priority not in ("low", "normal", "high"):
            raise ExtensionError("event: id lowercase letters, digits and _; priority low, normal or high")
        notify.EVENTS[id] = (label, priority, description)
        self._done.append(lambda: notify.EVENTS.pop(id, None))

    def on_audit(self, fn):
        """fn(entry) for every new audit log entry (a dict as stored) – keep it quick; it runs in a background thread"""
        h = (fn, self.name)
        _audit_hooks.append(h)
        self._done.append(lambda: _audit_hooks.remove(h))

    def add_backup_part(self, key, label, export, apply):
        """a part of Settings → Export / Import: export() → JSON-able data, apply(data) writes it back"""
        sid = f"x_{self.name}_{key}"
        if not re.match(r"^[a-z][a-z0-9_]{0,30}\Z", key or "") or sid in _backup_parts:
            raise ExtensionError(f"backup part {key!r}: lowercase letters, digits and _, once")
        _backup_parts[sid] = {"label": label, "export": export, "apply": apply, "ext": self.name}
        self._done.append(lambda: _backup_parts.pop(sid, None))

    # the license (configured extensions and signed packages only)
    def provide_license(self, features, edition):
        """features() → the feature names the license unlocks right now; edition e.g. "enterprise" – once, configured
        or signed only"""
        if self.origin not in TRUSTED:
            raise ExtensionError("only an extension from TC_EXTENSIONS or a package signed by tentaclAI can provide the license")
        if _provider:
            raise ExtensionError(f"{_provider['name']} provides the license already")
        _provider.update(name=self.name, features=features, edition=edition)
        self._done.append(_provider.clear)

    def _undo(self):
        for step in reversed(self._done):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass


_builtin_icon_names = []


def _builtin_icons():
    if not _builtin_icon_names:
        try:
            with open(os.path.join(os.path.dirname(__file__), "templates", "_icons.html")) as f:
                _builtin_icon_names.extend(re.findall(r'name == "([a-z0-9-]+)"', f.read()))
        except OSError:
            pass
    return _builtin_icon_names


# ---------------------------------------------------------------- loading

def _import_package(name, path):
    """a builtin/local package from its folder – without putting the folder on sys.path"""
    if name in sys.modules or importlib.util.find_spec(name) is not None:
        raise ExtensionError(f"the name {name} is taken by an installed Python module")
    spec = importlib.util.spec_from_file_location(name, os.path.join(path, "__init__.py"), submodule_search_locations=[path])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def _register(app, templates, name, origin_, mod):
    want = getattr(mod, "REQUIRES_API", None)
    if want != API_VERSION:
        raise ExtensionError(f"needs Extension API {want}, tentacontrol has {API_VERSION}" if want else
                             "declares no REQUIRES_API")
    if not callable(getattr(mod, "register", None)):
        raise ExtensionError("has no register(api)")
    api = Api(app, templates, name, origin_)
    try:
        mod.register(api)
    except BaseException:
        api._undo()
        raise


def _audit(name, action, decision="ok"):
    from . import auditlog
    auditlog.write("system", name, action, decision, actor="system", part="extension")


def load(app, templates):
    """import and register every configured and every enabled builtin/local extension – called before tentacontrol
    includes its own routers, so configured ones can replace pages"""
    env = templates.env
    if _prefix not in getattr(env.loader, "loaders", []):
        env.loader = ChoiceLoader([env.loader, _prefix])
    env.globals.update(ext_icons=_icons, ext_tabs=tabs, ext_help=help_sections, ext_static=static_url)
    for name in [n.strip() for n in os.environ.get("TC_EXTENSIONS", "").split(",") if n.strip()]:
        if name in LOADED:
            continue
        try:
            mod = importlib.import_module(name)
        except ImportError as e:
            if e.name != name:  # installed, but broken inside
                FAILED[name] = f"import failed: {e}"
                _exts[name] = {"name": name, "origin": "configured", "title": name, "description": "", "version": "",
                               "author": "", "homepage": "", "path": ""}
                log.warning(f"extension {name} failed to import: {e}")
                _audit(name, f"extension not loaded: import failed: {e}"[:300], "failed")
            continue
        _exts[name] = {"name": name, "origin": "configured", "title": getattr(mod, "TITLE", name),
                       "description": (getattr(mod, "DESCRIPTION", "") or "")[:300], "version": getattr(mod, "VERSION", ""),
                       "author": "", "homepage": "", "path": os.path.dirname(getattr(mod, "__file__", "") or "")}
        _load_one(app, templates, name, "configured", lambda m=mod: m)
    on = enabled()
    for name, info in _discover(say=True).items():
        if origin(name) == "configured":
            log.warning(f"extension {name} skipped – an extension from TC_EXTENSIONS has that name")
            continue
        if name in LOADED:
            continue
        _exts[name] = {k: info[k] for k in ("name", "origin", "title", "description", "version", "author", "homepage", "path")}
        _exts[name]["package"] = info.get("package")
        if info.get("package"):
            _pkg_loaded[name] = info["package"]["version"]  # what runs until the next start – also when it fails
        if name not in on and info["origin"] != "signed" and not (info.get("package") and info["error"]):
            continue  # a package that fails its check is reported even when it is off
        if info["error"]:
            FAILED[name] = info["error"]
            log.warning(f"extension {name} not loaded: {info['error']}")
            _audit(name, f"extension not loaded: {info['error']}"[:300], "failed")
            continue
        _load_one(app, templates, name, info["origin"], lambda n=name, p=info["path"]: _import_package(n, p))


def _load_one(app, templates, name, origin_, importer):
    try:
        mod = importer()
        _register(app, templates, name, origin_, mod)
    except Exception as e:  # noqa: BLE001 – a broken extension must not take tentacontrol down
        FAILED[name] = str(e) if isinstance(e, ExtensionError) else f"{type(e).__name__}: {e}"
        log.warning(f"extension {name} failed to register:\n{traceback.format_exc()}")
        _audit(name, f"extension not loaded: {FAILED[name]}"[:300], "failed")
        return
    LOADED.append(name)
    log.info(f"extension {name} loaded ({origin_})")
    _audit(name, f"extension loaded ({ORIGINS[origin_]})")


# ---------------------------------------------------------------- what pages and loops ask

def features():
    """feature names the license unlocks right now (empty without a license provider)"""
    if not _provider or not active(_provider["name"]):
        return set()
    try:
        return set(_provider["features"]() or ())
    except Exception:  # noqa: BLE001
        return set()


def edition():
    return _provider.get("edition", "community") if _provider and active(_provider["name"]) else "community"


def modules():
    """modules of active extensions, for the Modules page"""
    return [m for m in _modules if active(m["ext"])]


def licensed_modules():
    return [m for m in modules() if m["licensed"]]


def nav_entries(unlocked):
    """sidebar entries: [{href, label, icon, nav_id, count_url}] – active, not only planned, licensed ones unlocked"""
    out = []
    for m in modules():
        n = m.get("nav")
        if n and not m["planned"] and (not m["licensed"] or m["key"] in unlocked):
            href = n["href"]
            default_id = m["ext"] if href.startswith("/x/") else href.strip("/").split("/")[0]
            out.append({"href": href, "label": n["label"], "icon": n.get("icon") or "grid",
                        "nav_id": n.get("nav_id") or default_id, "count_url": m.get("count_url")})
    return out


def tabs(area):
    return [t for t in _tabs if t["area"] == area and active(t["ext"])]


def help_sections():
    return [h for h in _help if active(h["ext"])]


def banners(request):
    """the banners of active extensions for this page – a failing one is left out"""
    out = []
    for b in _banners:
        if not active(b["ext"]):
            continue
        try:
            r = b["fn"](request)
        except Exception as e:  # noqa: BLE001
            log.warning(f"extension {b['ext']}: banner: {e}")
            continue
        if isinstance(r, dict) and r.get("text"):
            out.append({"text": str(r["text"]), "kind": r.get("kind") if r.get("kind") in ("info", "warn", "err") else "info",
                        "href": r.get("href") or "", "link": r.get("link") or ""})
    return out


def tasks():
    return list(_tasks)


def audit_hooks():
    return [(fn, ext) for fn, ext in _audit_hooks if active(ext)]


def backup_parts():
    """section id → {label, export, apply, ext} of active extensions"""
    return {k: v for k, v in _backup_parts.items() if active(v["ext"])}


def static_url(name, path):
    """URL of an extension's static file, with its mtime against stale browser caches"""
    try:
        return f"/x/{name}/static/{path}?v={int(os.path.getmtime(os.path.join(_static[name], path)))}"
    except (KeyError, OSError):
        return f"/x/{name}/static/{path}"


def blocked_path(path):
    """True for /x/<name>/… of an extension that isn't active (disabled since the start, or never loaded)"""
    if not path.startswith("/x/"):
        return False
    return not active(path.split("/")[2] if path.count("/") >= 2 else "")
