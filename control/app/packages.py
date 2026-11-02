"""Module packages: an extension as a ZIP file, installed offline through Modules → Install from file.

Format 1 (docs/extensions.md → Packages):
    tcpkg.json   {"format": 1, "name", "version", "requires_api", "title", "files": {"<name>/path": "<sha256>", …}}
    tcpkg.sig    {"key": "<fingerprint>", "sig": "<base64url Ed25519 over the exact bytes of tcpkg.json>"}  – optional
    <name>/      the package (__init__.py, extension.json, templates/, static/ …)
A package signed with one of PACKAGE_KEYS gets the rights of a configured extension (origin "signed"); an unsigned
one is a third-party extension. A signature from an unknown key is an error, never "unsigned".

Installed packages live in PACKAGES_DIR/<name>/ (tcpkg.json, tcpkg.sig, <name>/); the version before an update in
PACKAGES_DIR/.prev/<name>/. verify_installed() checks every file again at each start – a changed file means the
package isn't loaded.
"""
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import time
import zipfile

from .central import b64d, fingerprint  # noqa: F401  (fingerprint: part of this module's API)
from .config import DATA_DIR

PACKAGES_DIR = os.path.join(DATA_DIR, "packages")
PREV_DIR = os.path.join(PACKAGES_DIR, ".prev")
# public keys (base64url, raw Ed25519) whose signature makes a package "signed" – the private half is in tcmanager.
# A list, so a new key can be added before the old one goes.
PACKAGE_KEYS = ["U8RedZWw0agzm3f0JAurOmEhoxmVR0Co-L876588JVs"]
FORMAT = 1
MAX_ZIP = 20 * 1024 * 1024
MAX_UNPACKED = 50 * 1024 * 1024
MAX_FILES = 2000
SUFFIXES = {".py", ".html", ".css", ".js", ".json", ".svg", ".png", ".woff2", ".md", ".txt"}
PLAIN_NAMES = {"LICENSE", "NOTICE"}
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")  # = extensions.NAME_RE
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,39}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class PackageError(ValueError):
    """the file isn't a package tentacontrol installs – the message says why"""


def _api_version():
    from .extensions import API_VERSION
    return API_VERSION


# ---------------------------------------------------------------- manifest and signature

def _manifest(raw):
    try:
        m = json.loads(raw)
    except ValueError:
        raise PackageError("tcpkg.json is not valid JSON") from None
    if not isinstance(m, dict):
        raise PackageError("tcpkg.json is not a JSON object")
    if m.get("format") != FORMAT:
        raise PackageError(f"package format {m.get('format')!r} – this tentacontrol reads format {FORMAT}")
    name, version = m.get("name"), m.get("version")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise PackageError("name: lowercase letters, digits and _ (2–41 characters)")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        raise PackageError("version: letters, digits and . + - (up to 40 characters)")
    if m.get("requires_api") != _api_version():
        raise PackageError(f"needs Extension API {m.get('requires_api')}, tentacontrol has {_api_version()}")
    files = m.get("files")
    if not isinstance(files, dict) or not files:
        raise PackageError("tcpkg.json lists no files")
    for path, sha in files.items():
        _check_path(path, name)
        if not isinstance(sha, str) or not SHA_RE.match(sha):
            raise PackageError(f"{path}: not a SHA-256 checksum")
    if not isinstance(m.get("title", ""), str):
        raise PackageError("title: text")
    return m


def _signature(raw_manifest, raw_sig, keys):
    """the fingerprint of the key that signed raw_manifest – PackageError if the signature is broken or the key unknown"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        s = json.loads(raw_sig)
        sig = b64d(s["sig"])
    except (ValueError, KeyError, TypeError):
        raise PackageError("tcpkg.sig is damaged") from None
    for pub in keys:
        try:
            Ed25519PublicKey.from_public_bytes(b64d(pub)).verify(sig, raw_manifest)
            return fingerprint(pub)
        except (ValueError, InvalidSignature):
            continue
    named = s.get("key") if isinstance(s.get("key"), str) else ""
    if named and named not in {fingerprint(k) for k in keys}:
        raise PackageError(f"signed with a key this tentacontrol doesn't know ({named[:19]})")
    raise PackageError("the signature doesn't match – the package was changed after signing")


def _check_path(path, name):
    if not isinstance(path, str) or not path.startswith(name + "/") or "\\" in path or "\0" in path:
        raise PackageError(f"{path!r}: every file belongs in the folder {name}/")
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts) or "__pycache__" in parts:
        raise PackageError(f"{path!r}: not a plain relative path")
    base = parts[-1]
    if os.path.splitext(base)[1].lower() not in SUFFIXES and base not in PLAIN_NAMES:
        raise PackageError(f"{path}: file type not allowed (only {', '.join(sorted(SUFFIXES))})")


# ---------------------------------------------------------------- reading a ZIP

def _read(data, keys):
    """(manifest, raw manifest, raw signature or None, signer fingerprint or "", {path: bytes}) – everything checked"""
    if len(data) > MAX_ZIP:
        raise PackageError(f"larger than {MAX_ZIP // 1024 // 1024} MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        raise PackageError("not a ZIP file") from None
    if len(infos) > MAX_FILES + 2:
        raise PackageError(f"more than {MAX_FILES} files")
    seen, total, raw = set(), 0, {}
    for i in infos:
        if i.filename in seen:
            raise PackageError(f"{i.filename}: twice in the ZIP")
        seen.add(i.filename)
        if i.flag_bits & 0x1:
            raise PackageError("encrypted ZIP files aren't supported")
        mode = i.external_attr >> 16
        if i.is_dir():
            continue
        if stat.S_IFMT(mode) and not stat.S_ISREG(mode):  # no type bits (many zip tools): a plain file
            raise PackageError(f"{i.filename}: not a plain file (symlink or device)")
        total += i.file_size
        if total > MAX_UNPACKED:
            raise PackageError(f"more than {MAX_UNPACKED // 1024 // 1024} MB unpacked")
        raw[i.filename] = i
    if "tcpkg.json" not in raw:
        raise PackageError("no tcpkg.json – not a tentaclAI module package")

    def content(info):
        with zf.open(info) as f:  # the header's size can lie: read at most one byte more than it says
            b = f.read(info.file_size + 1)
        if len(b) != info.file_size:
            raise PackageError(f"{info.filename}: size doesn't match the ZIP header")
        return b

    raw_manifest = content(raw.pop("tcpkg.json"))
    m = _manifest(raw_manifest)
    raw_sig = content(raw.pop("tcpkg.sig")) if "tcpkg.sig" in raw else None
    signer = _signature(raw_manifest, raw_sig, keys) if raw_sig is not None else ""
    listed = set(m["files"])
    extra, missing = sorted(set(raw) - listed), sorted(listed - set(raw))
    if extra:
        raise PackageError(f"{extra[0]}: in the ZIP, but not in tcpkg.json")
    if missing:
        raise PackageError(f"{missing[0]}: in tcpkg.json, but not in the ZIP")
    files = {}
    for path, info in raw.items():
        b = content(info)
        if hashlib.sha256(b).hexdigest() != m["files"][path]:
            raise PackageError(f"{path}: checksum doesn't match tcpkg.json")
        files[path] = b
    _check_package(m, files)
    return m, raw_manifest, raw_sig, signer, files


def _check_package(m, files):
    name = m["name"]
    if f"{name}/__init__.py" not in files:
        raise PackageError(f"no {name}/__init__.py")
    try:
        ext = json.loads(files[f"{name}/extension.json"])
    except KeyError:
        raise PackageError(f"no {name}/extension.json") from None
    except ValueError:
        raise PackageError("extension.json is not valid JSON") from None
    if not isinstance(ext, dict) or ext.get("name") != name:
        raise PackageError(f"extension.json names {ext.get('name') if isinstance(ext, dict) else None!r}, the package is {name!r}")
    if ext.get("requires_api") != m["requires_api"]:
        raise PackageError("extension.json and tcpkg.json need different Extension API versions")


def _summary(m, signer):
    return {"name": m["name"], "version": m["version"], "title": m.get("title") or m["name"],
            "requires_api": m["requires_api"], "signed": bool(signer), "key": signer, "files": len(m["files"])}


def inspect(data, keys=None):
    """what a ZIP contains, fully checked, nothing written: {name, version, title, requires_api, signed, key, files}
    plus "installed" (the version installed now, or "") – PackageError if it isn't a package tentacontrol installs"""
    m, _, _, signer, _ = _read(data, PACKAGE_KEYS if keys is None else keys)
    out = _summary(m, signer)
    out["installed"] = (installed().get(m["name"]) or {}).get("version", "")
    return out


# ---------------------------------------------------------------- installed packages

def _dir(name):
    if not NAME_RE.match(name or ""):
        raise PackageError("not a package name")
    return os.path.join(PACKAGES_DIR, name)


def install(data, allow_unsigned=False, keys=None):
    """check and unpack a package – the version installed before is kept for rollback(). Returns the summary."""
    m, raw_manifest, raw_sig, signer, files = _read(data, PACKAGE_KEYS if keys is None else keys)
    _managed(m["name"])
    if not signer and not allow_unsigned:
        raise PackageError("the package is not signed – confirm that you trust its code to install it")
    os.makedirs(PACKAGES_DIR, mode=0o700, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".new-", dir=PACKAGES_DIR)
    try:
        for path, b in files.items():
            dest = os.path.join(tmp, *path.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(b)
        with open(os.path.join(tmp, "tcpkg.json"), "wb") as f:
            f.write(raw_manifest)
        if raw_sig is not None:
            with open(os.path.join(tmp, "tcpkg.sig"), "wb") as f:
                f.write(raw_sig)
        target = _dir(m["name"])
        if os.path.isdir(target):
            prev = os.path.join(PREV_DIR, m["name"])
            os.makedirs(PREV_DIR, mode=0o700, exist_ok=True)
            shutil.rmtree(prev, ignore_errors=True)
            os.rename(target, prev)
        os.rename(tmp, target)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return _summary(m, signer)


def verify_installed(name, keys=None):
    """an installed package checked again: {name, version, title, signed, key, path, error} – path is the folder to
    import. Compiled caches are removed first, so only the checked sources run."""
    base = _dir(name)
    out = {"name": name, "version": "", "title": name, "signed": False, "key": "", "path": os.path.join(base, name),
           "error": ""}
    try:
        with open(os.path.join(base, "tcpkg.json"), "rb") as f:
            raw_manifest = f.read()
        m = _manifest(raw_manifest)
        out.update(version=m["version"], title=m.get("title") or name)
        if m["name"] != name:
            raise PackageError(f"tcpkg.json names {m['name']!r}, the folder is {name!r}")
        sig_file = os.path.join(base, "tcpkg.sig")
        if os.path.exists(sig_file):
            with open(sig_file, "rb") as f:
                out["key"] = _signature(raw_manifest, f.read(), PACKAGE_KEYS if keys is None else keys)
            out["signed"] = True
        found = {}
        for root, dirs, fnames in os.walk(base):
            if "__pycache__" in dirs:
                shutil.rmtree(os.path.join(root, "__pycache__"), ignore_errors=True)
                dirs.remove("__pycache__")
            for d in dirs:
                if os.path.islink(os.path.join(root, d)):
                    raise PackageError(f"{d}: a symlink in the package folder")
            for fn in fnames:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, base).replace(os.sep, "/")
                if rel in ("tcpkg.json", "tcpkg.sig"):
                    continue
                if os.path.islink(full) or not os.path.isfile(full):
                    raise PackageError(f"{rel}: not a plain file")
                with open(full, "rb") as f:
                    found[rel] = hashlib.sha256(f.read()).hexdigest()
        if set(found) != set(m["files"]):
            odd = sorted(set(found) ^ set(m["files"]))[0]
            raise PackageError(f"{odd}: added or removed after installing")
        changed = sorted(p for p, h in found.items() if m["files"][p] != h)
        if changed:
            raise PackageError(f"{changed[0]}: changed after installing")
    except OSError as e:
        out["error"] = f"can't read the package: {e.strerror or e}"
    except PackageError as e:
        out["error"] = str(e)
    if out["error"]:
        out["signed"] = False
    return out


def installed():
    """name → {version, title, signed, key, error, previous} for every package in PACKAGES_DIR"""
    out = {}
    for name in names():
        v = verify_installed(name)
        out[name] = {k: v[k] for k in ("version", "title", "signed", "key", "error", "path")}
        out[name]["previous"] = previous_version(name)
    return out


def names():
    """the installed packages' names (no checks)"""
    try:
        return sorted(n for n in os.listdir(PACKAGES_DIR) if NAME_RE.match(n) and os.path.isdir(os.path.join(PACKAGES_DIR, n)))
    except OSError:
        return []


def installed_versions():
    """name → version from tcpkg.json, without checking anything – cheap enough for every page"""
    return {n: _version_of(os.path.join(PACKAGES_DIR, n)) for n in names()}


def is_signed(name):
    """has a signature file (not checked)"""
    return os.path.isfile(os.path.join(_dir(name), "tcpkg.sig"))


def previous_version(name):
    """the version kept for rollback(), or """""
    return _version_of(os.path.join(PREV_DIR, name))


def _version_of(base):
    try:
        with open(os.path.join(base, "tcpkg.json")) as f:
            return str(json.load(f).get("version") or "?")
    except (OSError, ValueError, AttributeError):
        return ""


# ---------------------------------------------------------------- an upload waiting for its confirmation

UPLOAD_TTL = 3600


def keep(data):
    """keep an uploaded ZIP until the admin confirms it (one at a time, an hour at most)"""
    os.makedirs(PACKAGES_DIR, mode=0o700, exist_ok=True)
    fd = os.open(_upload(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def pending():
    """the kept upload (bytes), or None when there is none or it is older than an hour"""
    try:
        if time.time() - os.path.getmtime(_upload()) > UPLOAD_TTL:
            drop_pending()
            return None
        with open(_upload(), "rb") as f:
            return f.read()
    except OSError:
        return None


def drop_pending():
    try:
        os.remove(_upload())
    except OSError:
        pass


def _upload():
    return os.path.join(PACKAGES_DIR, ".upload.zip")  # PACKAGES_DIR read at call time (tests move it)


def _managed(name):
    """PackageError when the central server manages this module (its profile installs it) – unless it applies the profile"""
    from .central import check_write
    try:
        check_write("modules", name)
    except ValueError as e:
        raise PackageError(str(e)) from None


def remove(name):
    """delete an installed package (and its kept previous version)"""
    target = _dir(name)
    _managed(name)
    if not os.path.isdir(target):
        raise PackageError(f"no package {name}")
    shutil.rmtree(target)
    shutil.rmtree(os.path.join(PREV_DIR, name), ignore_errors=True)


def rollback(name):
    """swap the installed package with the version kept from before the last update – returns the version now installed"""
    target, prev = _dir(name), os.path.join(PREV_DIR, name)
    _managed(name)
    if not os.path.isdir(prev):
        raise PackageError(f"no earlier version of {name} kept")
    swap = tempfile.mkdtemp(prefix=".swap-", dir=PACKAGES_DIR)
    os.rmdir(swap)
    if os.path.isdir(target):
        os.rename(target, swap)
    os.rename(prev, target)
    if os.path.isdir(swap):
        os.rename(swap, prev)
    return _version_of(target)
