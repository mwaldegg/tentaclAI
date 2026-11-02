"""Module packages (control/app/packages.py): the ZIP format, signatures, the checks against crafted ZIPs, install,
the check at start, rollback and remove – with throwaway keys."""
import base64
import hashlib
import io
import json
import os
import stat
import warnings
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def new_key():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, b64e(pub)


def files_of(name="tcx_pkg", version="1.0.0"):
    return {f"{name}/__init__.py": b"REQUIRES_API = 1\ndef register(api):\n    pass\n",
            f"{name}/extension.json": json.dumps({"name": name, "title": "Package test", "version": version,
                                                  "requires_api": 1}).encode(),
            f"{name}/templates/page.html": b"<p>hi</p>"}


def build(name="tcx_pkg", version="1.0.0", files=None, priv=None, manifest=None, extra=(), sig=None):
    """a package ZIP: files (path → bytes), signed with priv; manifest overrides fields of tcpkg.json;
    extra = (ZipInfo or name, bytes) added after the listed files; sig replaces tcpkg.sig"""
    files = files_of(name, version) if files is None else files
    m = {"format": 1, "name": name, "version": version, "requires_api": 1, "title": "Package test",
         "files": {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}}
    m.update(manifest or {})
    raw = json.dumps(m, indent=1).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z, warnings.catch_warnings():
        warnings.simplefilter("ignore")  # a duplicate name is one of the tests
        z.writestr("tcpkg.json", raw)
        if sig is not None:
            z.writestr("tcpkg.sig", sig)
        elif priv:
            z.writestr("tcpkg.sig", json.dumps({"key": "", "sig": b64e(priv.sign(raw))}))
        for p, b in files.items():
            z.writestr(p, b)
        for info, b in extra:
            z.writestr(info, b)
    return buf.getvalue()


@pytest.fixture
def pk(app_module, tmp_path, monkeypatch):
    """packages with PACKAGES_DIR in tmp_path and one trusted throwaway key; returns (module, private key)"""
    from app import packages
    priv, pub = new_key()
    monkeypatch.setattr(packages, "PACKAGES_DIR", str(tmp_path / "packages"))
    monkeypatch.setattr(packages, "PREV_DIR", str(tmp_path / "packages" / ".prev"))
    monkeypatch.setattr(packages, "PACKAGE_KEYS", [pub])
    return packages, priv


def test_signed_and_unsigned_packages(pk):
    packages, priv = pk
    s = packages.inspect(build(priv=priv))
    assert s["signed"] and s["key"] == packages.fingerprint(packages.PACKAGE_KEYS[0]) and s["version"] == "1.0.0"
    assert s["files"] == 3 and s["installed"] == ""
    u = packages.inspect(build())
    assert not u["signed"] and u["key"] == ""
    other, _ = new_key()
    with pytest.raises(packages.PackageError, match="doesn't match"):  # a key nobody named, not ours
        packages.inspect(build(priv=other))
    raw = json.dumps({"key": "AAAA BBBB CCCC DDDD", "sig": b64e(other.sign(b"x"))})
    with pytest.raises(packages.PackageError, match="doesn't know"):
        packages.inspect(build(sig=raw))
    with pytest.raises(packages.PackageError, match="damaged"):
        packages.inspect(build(sig="not json"))


def test_tampering_breaks_the_signature(pk):
    packages, priv = pk
    data = build(priv=priv)
    # change one byte of tcpkg.json inside the ZIP: the signature no longer matches
    zin = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in zin.infolist():
            b = zin.read(i)
            z.writestr(i.filename, b.replace(b'"1.0.0"', b'"9.0.0"') if i.filename == "tcpkg.json" else b)
    with pytest.raises(packages.PackageError, match="changed after signing"):
        packages.inspect(buf.getvalue())
    # swap a file but keep the signed tcpkg.json: its checksum catches it
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in zin.infolist():
            b = zin.read(i)
            z.writestr(i.filename, b"import os  # evil\n" if i.filename == "tcx_pkg/__init__.py" else b)
    with pytest.raises(packages.PackageError, match="__init__.py: checksum"):
        packages.inspect(buf.getvalue())


@pytest.mark.parametrize("kw, msg", [
    ({"manifest": {"format": 2}}, "format"),
    ({"manifest": {"name": "Bad-Name"}}, "name"),
    ({"manifest": {"version": "1 0"}}, "version"),
    ({"manifest": {"requires_api": 99}}, "Extension API"),
    ({"manifest": {"files": {}}}, "no files"),
    ({"extra": [("tcx_pkg/sneaky.py", b"x")]}, "not in tcpkg.json"),
    ({"extra": [("tcx_pkg/__init__.py", b"again")]}, "twice"),
    ({"files": {"tcx_pkg/__init__.py": b"", "../evil.py": b"x"}}, "belongs in the folder"),
    ({"files": {"tcx_pkg/__init__.py": b"", "tcx_pkg/../../evil.py": b"x"}}, "plain relative path"),
    ({"files": {"tcx_pkg/__init__.py": b"", "/etc/evil.py": b"x"}}, "belongs in the folder"),
    ({"files": {"tcx_pkg/__init__.py": b"", "tcx_pkg/lib.so": b"x"}}, "file type"),
    ({"files": {"tcx_pkg/__init__.py": b"", "tcx_pkg/__pycache__/x.py": b"x"}}, "plain relative path"),
    ({"files": {"tcx_pkg/extension.json": b"{}", "tcx_pkg/x.py": b""}}, "__init__.py"),
    ({"files": {"tcx_pkg/__init__.py": b""}}, "extension.json"),
    ({"files": {"tcx_pkg/__init__.py": b"", "tcx_pkg/extension.json": b'{"name": "other", "requires_api": 1}'}}, "names 'other'"),
])
def test_refused_packages(pk, kw, msg):
    packages, priv = pk
    with pytest.raises(packages.PackageError, match=msg):
        packages.inspect(build(priv=priv, **kw))


def test_refused_zip_files(pk):
    packages, priv = pk
    with pytest.raises(packages.PackageError, match="not a ZIP"):
        packages.inspect(b"PK not really")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("tcx_pkg/__init__.py", b"")
    with pytest.raises(packages.PackageError, match="no tcpkg.json"):
        packages.inspect(buf.getvalue())
    link = zipfile.ZipInfo("tcx_pkg/link.py")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    files = files_of()
    files["tcx_pkg/link.py"] = b"/etc/passwd"
    data = build(priv=priv, files={k: v for k, v in files.items() if k != "tcx_pkg/link.py"},
                 manifest={"files": {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}},
                 extra=[(link, b"/etc/passwd")])
    with pytest.raises(packages.PackageError, match="symlink"):
        packages.inspect(data)


def test_size_limits(pk, monkeypatch):
    packages, priv = pk
    monkeypatch.setattr(packages, "MAX_UNPACKED", 100)
    with pytest.raises(packages.PackageError, match="unpacked"):  # a small ZIP that unpacks big
        packages.inspect(build(priv=priv, files=dict(files_of(), **{"tcx_pkg/big.txt": b"0" * 5000})))
    monkeypatch.setattr(packages, "MAX_ZIP", 10)
    with pytest.raises(packages.PackageError, match="larger than"):
        packages.inspect(build(priv=priv))


def test_install_verify_update_rollback_remove(pk):
    packages, priv = pk
    with pytest.raises(packages.PackageError, match="not signed"):
        packages.install(build())
    s = packages.install(build(priv=priv))
    assert s["signed"] and s["name"] == "tcx_pkg"
    base = os.path.join(packages.PACKAGES_DIR, "tcx_pkg")
    assert os.path.isfile(os.path.join(base, "tcx_pkg", "__init__.py")) and os.path.isfile(os.path.join(base, "tcpkg.sig"))
    v = packages.verify_installed("tcx_pkg")
    assert v["signed"] and not v["error"] and v["path"] == os.path.join(base, "tcx_pkg")
    assert packages.inspect(build(priv=priv, version="1.1.0"))["installed"] == "1.0.0"

    os.makedirs(os.path.join(base, "tcx_pkg", "__pycache__"))  # compiled caches are removed, not counted
    open(os.path.join(base, "tcx_pkg", "__pycache__", "x.pyc"), "wb").close()
    assert not packages.verify_installed("tcx_pkg")["error"]
    assert not os.path.exists(os.path.join(base, "tcx_pkg", "__pycache__"))

    packages.install(build(priv=priv, version="1.1.0"))
    inst = packages.installed()["tcx_pkg"]
    assert inst["version"] == "1.1.0" and inst["previous"] == "1.0.0" and inst["signed"]
    assert packages.rollback("tcx_pkg") == "1.0.0"
    assert packages.installed()["tcx_pkg"]["previous"] == "1.1.0"
    packages.remove("tcx_pkg")
    assert packages.installed() == {}
    with pytest.raises(packages.PackageError, match="no earlier version"):
        packages.rollback("tcx_pkg")
    with pytest.raises(packages.PackageError, match="not a package name"):
        packages.remove("../x")


def test_unsigned_install_and_changes_after_installing(pk):
    packages, priv = pk
    assert not packages.install(build(), allow_unsigned=True)["signed"]
    assert not packages.verify_installed("tcx_pkg")["error"]
    packages.install(build(priv=priv))
    pkg = os.path.join(packages.PACKAGES_DIR, "tcx_pkg", "tcx_pkg")
    with open(os.path.join(pkg, "__init__.py"), "a") as f:
        f.write("# changed\n")
    v = packages.verify_installed("tcx_pkg")
    assert "__init__.py: changed after installing" in v["error"] and not v["signed"]
    packages.install(build(priv=priv))
    open(os.path.join(pkg, "added.py"), "w").close()
    assert "added.py: added or removed" in packages.verify_installed("tcx_pkg")["error"]
    packages.install(build(priv=priv))
    with open(os.path.join(packages.PACKAGES_DIR, "tcx_pkg", "tcpkg.json"), "a") as f:
        f.write(" ")
    assert "changed after signing" in packages.verify_installed("tcx_pkg")["error"]


def test_key_removed_from_the_trusted_list(pk, monkeypatch):
    packages, priv = pk
    packages.install(build(priv=priv))
    monkeypatch.setattr(packages, "PACKAGE_KEYS", [])
    v = packages.verify_installed("tcx_pkg")
    assert v["error"] and not v["signed"]


# ---------------------------------------------------------------- in tentacontrol: Modules → Install from file

PROVIDER = '''REQUIRES_API = 1
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
router = APIRouter()
@router.get("/license")
async def lic():
    return PlainTextResponse("from the package")
def register(api):
    api.add_router(router)
    api.provide_license(lambda: {"reports"}, "enterprise")
'''


def provider_files(name="tcx_ent", version="1.0.0"):
    f = files_of(name, version)
    f[f"{name}/__init__.py"] = PROVIDER.encode()
    return f


def upload(client, data):
    return client.post("/modules/upload", files={"file": ("p.tcpkg.zip", data, "application/zip")})


def test_signed_package_installs_like_enterprise(client, ext, pk):
    packages, priv = pk
    html = upload(client, build("tcx_ent", files=provider_files(), priv=priv)).text
    assert "signed by tentaclAI" in html and "Install 1.0.0" in html and "I trust this code" not in html
    r = client.post("/modules/upload/install")
    assert r.headers.get("hx-refresh") == "true" and packages.pending() is None
    assert "Restart needed" in client.get("/modules").text and "tcx_ent" in ext.mod.restart_pending()
    ext.reload()  # = the restart
    assert ext.mod.LOADED == ["tcx_ent"] and ext.mod.origin("tcx_ent") == "signed" and ext.mod.features() == {"reports"}
    assert client.get("/license").text == "from the package"  # signed: may replace tentacontrol's pages
    assert ext.mod.restart_pending() == []
    html = client.get("/modules").text
    assert "Signed by tentaclAI" in html and "Package 1.0.0" in html and "/modules/tcx_ent/remove" in html and "Roll back" not in html
    with pytest.raises(ValueError, match="always on"):
        ext.mod.set_enabled("tcx_ent", False)
    upload(client, build("tcx_ent", "1.1.0", files=provider_files(version="1.1.0"), priv=priv))
    client.post("/modules/upload/install")
    assert "tcx_ent" in ext.mod.restart_pending() and "1.0.0 kept" in client.get("/modules").text
    client.post("/modules/tcx_ent/rollback")
    assert packages.installed_versions() == {"tcx_ent": "1.0.0"} and ext.mod.restart_pending() == []
    client.post("/modules/tcx_ent/remove")
    assert packages.names() == [] and ext.mod.restart_pending() == ["tcx_ent"]  # still running until the restart
    from app import auditlog
    actions = [e["action"] for e in auditlog.search("target:tcx_ent", rng="1h")[0]]
    assert any("module package installed: Package test 1.0.0 (signed by tentaclAI" in a for a in actions)
    assert any("rolled back to 1.0.0" in a for a in actions) and any(a == "module package removed" for a in actions)


def test_unsigned_package_is_third_party(client, ext, pk):
    packages, priv = pk
    data = build("tcx_ent", files=provider_files())
    assert "I trust this code" in upload(client, data).text
    r = client.post("/modules/upload/install")
    assert "not signed" in r.headers.get("hx-trigger", "") and packages.names() == []
    client.post("/modules/upload/install", data={"trust": "1"})
    assert packages.names() == ["tcx_ent"] and "tcx_ent" in ext.mod.enabled()
    ext.reload()
    assert ext.mod.origin("tcx_ent") == "local" and "routes must start with /x/tcx_ent/" in ext.mod.FAILED["tcx_ent"]
    html = client.get("/modules").text
    assert "Third-party" in html and "unsigned" in html
    client.post("/modules/tcx_ent/remove")
    assert "tcx_ent" not in ext.mod.enabled() and packages.names() == []


def test_changed_package_is_not_loaded(client, ext, pk):
    packages, priv = pk
    packages.install(build("tcx_hi", priv=priv))
    with open(os.path.join(packages.PACKAGES_DIR, "tcx_hi", "tcx_hi", "__init__.py"), "a") as f:
        f.write("import os\n")
    ext.reload()
    assert "tcx_hi" not in ext.mod.LOADED and "changed after installing" in ext.mod.FAILED["tcx_hi"]
    assert "changed after installing" in client.get("/modules").text


def test_refused_uploads(client, ext, pk):
    packages, priv = pk
    assert "Not installed: not a ZIP file" in upload(client, b"nope").text
    ext.install("tcx_ent", {"__init__.py": PROVIDER}, origin="configured")
    ext.reload("tcx_ent")
    assert "TC_EXTENSIONS" in upload(client, build("tcx_ent", files=provider_files(), priv=priv)).text
    ext.install("tcx_loc", {"__init__.py": "def register(api):\n    pass\n"})
    assert "local/extensions/tcx_loc" in upload(client, build("tcx_loc", priv=priv)).text
    r = client.post("/modules/upload/install")
    assert "expired" in r.headers.get("hx-trigger", "")


# ---------------------------------------------------------------- scripts/tcpkg.py: building a package

def _tcpkg():
    import importlib.util
    spec = importlib.util.spec_from_file_location("tcpkg", os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "tcpkg.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_tcpkg_builds_what_tentacontrol_installs(pk, tmp_path):
    packages, priv = pk
    tcpkg = _tcpkg()
    for name in ("FORMAT", "SUFFIXES", "PLAIN_NAMES"):
        assert getattr(tcpkg, name) == getattr(packages, name), name
    hello = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples", "extensions", "tcx_hello")
    src = tmp_path / "src" / "tcx_hello"
    import shutil
    shutil.copytree(hello, src)
    os.makedirs(src / "__pycache__")
    (src / "__pycache__" / "x.pyc").write_bytes(b"")  # left out
    (src / ".DS_Store").write_bytes(b"")
    target, m = tcpkg.build(str(src), str(tmp_path))
    assert target.endswith("tcx_hello-1.0.0.tcpkg.zip") and not any("__pycache__" in f or ".DS_Store" in f for f in m["files"])
    info = packages.inspect(open(target, "rb").read())
    assert info["name"] == "tcx_hello" and info["version"] == "1.0.0" and not info["signed"]
    assert tcpkg.build(str(src), str(tmp_path / "x.zip"), version="2.0.0-rc1")[1]["version"] == "2.0.0-rc1"
    (src / "lib.so").write_bytes(b"")
    with pytest.raises(SystemExit, match="file type not allowed"):
        tcpkg.build(str(src), str(tmp_path))


def test_a_file_and_a_folder_of_the_same_name(pk):
    """x/a.py and x/a.py/b.py passed every check, unpacking then raised an OSError (a 500, a central sync that died)"""
    packages, priv = pk
    files = dict(files_of(), **{"tcx_pkg/templates/page.html/inner.html": b"x"})
    with pytest.raises(packages.PackageError, match="a file and a folder of the same name"):
        packages.install(build(files=files, priv=priv))
