"""SSH certificates: the CA in tentacontrol, the host files (login "cert", principal, the generated Match blocks) and
the scripts that change authorized_keys on a host – run here with sh against a temporary home."""
import os
import subprocess
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import ssh as sshformat

import tclib


def _pub(key):
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


@pytest.fixture
def conf_d(tmp_path):
    d = tmp_path / "config.d"
    d.mkdir()
    return str(d)


@pytest.fixture
def certhost(app_module):
    """a host with login cert in the fixture stack (removed afterwards)"""
    from app import sshhosts
    sshhosts.add({"alias": "certbox", "hostname": "certbox.example.test", "user": "deploy", "port": "22", "access": "confirm"})
    h = sshhosts.get("certbox")
    sshhosts.update("certbox", dict(h, auth="cert", principal="tentaclai-certbox"))
    yield sshhosts.get("certbox")
    sshhosts.remove("certbox")


def test_host_login_round_trip(conf_d):
    tclib.ssh_add(conf_d, {"alias": "nas", "hostname": "nas.example.test", "user": "admin"})
    h = tclib.ssh_host(conf_d, "nas")
    assert (h["auth"], h["principal"], tclib.ssh_principal(h)) == ("key", "", "tentaclai-nas")
    assert not os.path.exists(os.path.join(conf_d, tclib.CERT_CONF))
    tclib.ssh_update(conf_d, "nas", dict(h, auth="cert", principal="tentaclai-nas"))
    conf = open(os.path.join(conf_d, tclib.CERT_CONF)).read()
    assert 'Match originalhost nas exec "/usr/local/bin/tc-cert nas"' in conf
    assert "CertificateFile ~/.ssh/certs/nas-cert.pub" in conf
    assert [x["alias"] for x in tclib.ssh_hosts(conf_d)] == ["nas"]  # the generated file holds no host
    # a rename keeps the principal – the host's CA line names it
    tclib.ssh_update(conf_d, "nas", dict(tclib.ssh_host(conf_d, "nas"), alias="nas2"))
    h = tclib.ssh_host(conf_d, "nas2")
    assert (h["auth"], tclib.ssh_principal(h)) == ("cert", "tentaclai-nas")
    assert "originalhost nas2 " in open(os.path.join(conf_d, tclib.CERT_CONF)).read()
    # back to the key: no Match block, the cached certificate goes, the principal stays for a later switch
    certs = os.path.join(os.path.dirname(conf_d), "certs")
    os.makedirs(certs)
    for f in ("nas2", "nas2.pub", "nas2-cert.pub", "nas2.json", "other-cert.pub"):
        open(os.path.join(certs, f), "w").close()
    tclib.ssh_cert_conf(conf_d)
    assert len(os.listdir(certs)) == 4  # nas2 still uses certificates, "other" is gone
    tclib.ssh_update(conf_d, "nas2", dict(h, auth="key"))
    assert not os.path.exists(os.path.join(conf_d, tclib.CERT_CONF)) and os.listdir(certs) == []
    assert tclib.ssh_host(conf_d, "nas2")["principal"] == "tentaclai-nas"


def test_host_login_validation(conf_d):
    with pytest.raises(ValueError, match="login"):
        tclib.ssh_validate({"alias": "a", "hostname": "h", "user": "u", "auth": "password"})
    with pytest.raises(ValueError, match="principal"):
        tclib.ssh_validate({"alias": "a", "hostname": "h", "user": "u", "auth": "cert", "principal": 'x" ssh-rsa'})
    with open(os.path.join(conf_d, "odd.conf"), "w") as f:
        f.write("Host odd\n    HostName odd.test\n    # tentaclai: auth=sometimes\n")
    assert tclib.ssh_host(conf_d, "odd")["auth"] == "key"  # unknown value: the key


def test_ca_issues_short_certificates(certhost, monkeypatch):
    from app import sshca
    monkeypatch.setattr(sshca, "read_env", lambda: {"SSH_CERT_MINUTES": "2", "TC_HOSTNAME": "box"})
    user = ed25519.Ed25519PrivateKey.generate()
    line, before = sshca.issue("certbox", _pub(user))
    cert = sshformat.load_ssh_public_identity(line.encode())
    assert isinstance(cert, sshformat.SSHCertificate)
    cert.verify_cert_signature()
    ca = serialization.load_ssh_public_key(" ".join(sshca.public_line().split()[:2]).encode())
    assert cert.signature_key().public_bytes_raw() == ca.public_bytes_raw()
    assert cert.valid_principals == [b"tentaclai-certbox"] and cert.type == sshformat.SSHCertificateType.USER
    assert abs(cert.valid_before - (time.time() + 120)) < 5 and cert.valid_before == before
    assert cert.extensions == {b"permit-pty": b""} and cert.critical_options == {}
    second, _ = sshca.issue("certbox", _pub(user))
    assert sshformat.load_ssh_public_identity(second.encode()).serial == cert.serial + 1
    assert sshca.public_line().endswith(" tentaclai-ca@box")


@pytest.mark.parametrize("minutes, expect", [("", 5), ("0", 1), ("90", 60), ("x", 5), ("15", 15)])
def test_ca_lifetime_is_bounded(monkeypatch, app_module, minutes, expect):
    from app import sshca
    monkeypatch.setattr(sshca, "read_env", lambda: {"SSH_CERT_MINUTES": minutes})
    assert sshca.minutes() == expect


def test_ca_refuses(certhost, app_module):
    from app import sshca, sshhosts
    pub = _pub(ed25519.Ed25519PrivateKey.generate())
    sshhosts.add({"alias": "keybox", "hostname": "k.example.test", "user": "u"})
    try:
        with pytest.raises(ValueError, match="does not log in with certificates"):
            sshca.issue("keybox", pub)
    finally:
        sshhosts.remove("keybox")
    with pytest.raises(ValueError, match="does not log in"):
        sshca.issue("nosuchhost", pub)
    with pytest.raises(ValueError, match="only ed25519"):
        sshca.issue("certbox", _pub(rsa.generate_private_key(public_exponent=65537, key_size=2048)))
    with pytest.raises(ValueError, match="not an OpenSSH"):
        sshca.issue("certbox", "ssh-ed25519 garbage")


def test_internal_endpoint_needs_the_svc_token(certhost, logged_in):
    from app import activity
    pub = _pub(ed25519.Ed25519PrivateKey.generate())
    assert logged_in.post("/internal/ssh-cert", json={"alias": "certbox", "public_key": pub}).status_code in (401, 403)
    activity.ensure_token()
    token = open(activity.TOKEN_FILE).read().strip()
    r = logged_in.post("/internal/ssh-cert", json={"alias": "certbox", "public_key": pub}, headers={"X-TC-Token": token})
    assert r.status_code == 200 and r.json()["certificate"].startswith("ssh-ed25519-cert-v01@openssh.com ")
    r = logged_in.post("/internal/ssh-cert", json={"alias": "nosuchhost", "public_key": pub}, headers={"X-TC-Token": token})
    assert r.status_code == 400


def _run(home, script):
    r = subprocess.run(["sh", "-c", script], env={"HOME": str(home), "PATH": os.environ["PATH"]}, capture_output=True, text=True)
    return r.stdout + r.stderr


KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeyBodyKeyBodyKeyBodyKeyBodyKeyBody tentaclai@box"
CA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaBodyCaBodyCaBodyCaBodyCaBodyCaBody0 tentaclai-ca@box"


def test_host_scripts_switch_and_keep_options(tmp_path):
    from app import sshops
    ak = tmp_path / ".ssh" / "authorized_keys"
    ak.parent.mkdir()
    ak.write_text(f"ssh-ed25519 AAAAother admin@laptop\nfrom=\"10.0.0.1\",no-agent-forwarding {KEY}\n")
    out = _run(tmp_path, sshops.install_ca_script(KEY.split()[1], CA, "tentaclai-box"))
    assert "TC_CA_ADDED" in out
    lines = ak.read_text().splitlines()
    assert lines[-1] == f'cert-authority,principals="tentaclai-box",from="10.0.0.1",no-agent-forwarding {CA}'
    # again with another principal: the old CA line is replaced, not doubled
    _run(tmp_path, sshops.install_ca_script(KEY.split()[1], CA, "tentaclai-box2"))
    assert sum(CA.split()[1] in l for l in ak.read_text().splitlines()) == 1 and "box2" in ak.read_text()
    # drop the key: the admin's own key and the CA line stay
    assert "TC_REMOVED" in _run(tmp_path, sshops.unauthorize_script([KEY.split()[1]]))
    assert ak.read_text().splitlines() == ["ssh-ed25519 AAAAother admin@laptop",
                                           f'cert-authority,principals="tentaclai-box2",from="10.0.0.1",no-agent-forwarding {CA}']
    # back to the key: it gets the CA line's options; then the CA line goes
    assert "TC_KEY_ADDED" in _run(tmp_path, sshops.install_key_script(KEY, CA.split()[1]))
    assert ak.read_text().splitlines()[-1] == f'from="10.0.0.1",no-agent-forwarding {KEY}'
    _run(tmp_path, sshops.install_key_script(KEY, CA.split()[1]))  # twice: no second line
    assert ak.read_text().count(KEY.split()[1]) == 1
    _run(tmp_path, sshops.unauthorize_script([CA.split()[1]]))
    assert ak.read_text().splitlines() == ["ssh-ed25519 AAAAother admin@laptop", f'from="10.0.0.1",no-agent-forwarding {KEY}']


def test_host_scripts_without_options(tmp_path):
    from app import sshops
    out = _run(tmp_path, sshops.install_ca_script(KEY.split()[1], CA, "tentaclai-box"))  # no ~/.ssh yet
    assert "TC_CA_ADDED" in out
    assert (tmp_path / ".ssh" / "authorized_keys").read_text() == f'cert-authority,principals="tentaclai-box" {CA}\n'
    _run(tmp_path, sshops.install_key_script(KEY, CA.split()[1]))
    assert (tmp_path / ".ssh" / "authorized_keys").read_text().splitlines()[-1] == KEY
    with pytest.raises(RuntimeError):
        sshops.install_ca_script("x", CA, 'p" ssh-rsa AAAA')


@pytest.mark.parametrize("takes_cert", [True, False])
def test_switch_to_certificates_and_back(certhost, logged_in, monkeypatch, takes_cert):
    """key → cert: CA line on, login cert, checked – a host that doesn't take it goes back to the key (CA line off);
    cert → key: key on, checked with the key, CA line off"""
    from app import dockerops, sshhosts, sshops
    sshhosts.update("certbox", dict(certhost, auth="key"))
    calls = []
    monkeypatch.setattr(sshops, "install_ca", lambda alias, p: calls.append(("ca", alias, p)))
    monkeypatch.setattr(sshops, "install_key", lambda alias: calls.append(("key", alias)))
    monkeypatch.setattr(sshops, "unauthorize", lambda alias, key=True, ca=True: calls.append(("off", key, ca)))
    monkeypatch.setattr(sshops, "cert_login", lambda alias: (takes_cert, "Permission denied (publickey)"))
    monkeypatch.setattr(dockerops, "ssh_check", lambda alias, sudo="": (0, f"deploy@{alias}\n"))
    html = logged_in.post("/ssh/certbox/login/cert", data={"remove_key": "1"}).text
    if not takes_cert:
        assert "did not accept the certificate" in html and sshhosts.get("certbox")["auth"] == "key"
        assert calls == [("ca", "certbox", "tentaclai-certbox"), ("off", False, True)]
        return
    assert "Permanent key removed" in html and sshhosts.get("certbox")["auth"] == "cert"
    assert calls == [("ca", "certbox", "tentaclai-certbox"), ("off", True, False)]
    assert "certificate" in logged_in.get("/ssh/certbox/login").text
    calls.clear()
    html = logged_in.post("/ssh/certbox/login/key").text
    assert "logs in with the key" in html and sshhosts.get("certbox")["auth"] == "key"
    assert calls == [("key", "certbox"), ("off", False, True)]


def test_failed_check_on_a_cert_host_changes_nothing(certhost, logged_in, monkeypatch):
    """a host already on certificates whose check fails (e.g. "Remove the permanent key" while it is unreachable)
    stays on certificates – no switch back to a key it may no longer accept, the CA line stays"""
    from app import sshhosts, sshops
    sshhosts.update("certbox", dict(certhost, auth="cert", principal="tentaclai-certbox"))
    calls = []
    monkeypatch.setattr(sshops, "install_ca", lambda alias, p: calls.append(("ca", alias, p)))
    monkeypatch.setattr(sshops, "unauthorize", lambda alias, key=True, ca=True: calls.append(("off", key, ca)))
    monkeypatch.setattr(sshops, "cert_login", lambda alias: (False, "Connection timed out"))
    html = logged_in.post("/ssh/certbox/login/cert", data={"remove_key": "1"}).text
    assert "certificate check failed" in html and "back to the key" not in html
    assert sshhosts.get("certbox")["auth"] == "cert" and calls == []

def test_ca_line_per_host(certhost, logged_in):
    html = logged_in.get("/ssh/certbox/caline").text
    assert 'cert-authority,principals=&#34;tentaclai-certbox&#34; ssh-ed25519 ' in html or \
        'cert-authority,principals="tentaclai-certbox" ssh-ed25519 ' in html
    page = logged_in.get("/ssh").text
    assert "/ssh/certbox/caline" in page and "&lt;alias&gt;" not in page


def test_manual_commands_add_the_line(tmp_path):
    """the command shown for adding a line by hand works as written (as the user) – quotes of the CA line included"""
    from app import sshops
    line = f'cert-authority,principals="tentaclai-box" {CA}'
    cmds = sshops.manual_commands("deploy", line)
    assert [w for w, _ in cmds] == ["as deploy", "as root"] and "getent passwd deploy" in cmds[1][1]
    assert [w for w, _ in sshops.manual_commands("root", line)] == ["as root"]
    _run(tmp_path, cmds[0][1])
    _run(tmp_path, cmds[0][1])
    assert (tmp_path / ".ssh" / "authorized_keys").read_text().splitlines() == [line, line]
    assert oct((tmp_path / ".ssh").stat().st_mode)[-3:] == "700"


def test_add_host_by_hand_with_certificates(app_module, logged_in, monkeypatch):
    """Add host, CA line added by hand: "Already authorized" with certificates ticked saves login cert and checks it"""
    from app import dockerops, sshhosts, sshops
    page = logged_in.post("/ssh/new/form", data={"alias": "handbox", "hostname": "h.example.test", "user": "pi"}).text
    monkeypatch.setattr(sshops, "cert_login", lambda alias: (True, ""))
    monkeypatch.setattr(dockerops, "ssh_check", lambda alias, sudo="": (0, f"pi@{alias}\n"))
    try:
        html = logged_in.post("/ssh/new/deploy", data={"alias": "handbox", "hostname": "h.example.test", "user": "pi",
                                                       "port": "22", "access": "confirm", "mode": "skip", "cert": "1"}).text
        assert "Logs in with a certificate" in html
        h = sshhosts.get("handbox")
        assert (h["auth"], h["principal"]) == ("cert", "tentaclai-handbox")
    finally:
        sshhosts.remove("handbox")
    assert page  # the form step renders


def test_deploy_step_shows_both_manual_commands(app_module, logged_in, monkeypatch):
    from app import sshops
    monkeypatch.setattr(sshops, "trust", lambda token: None)
    html = logged_in.post("/ssh/new/trust", data={"alias": "nas", "hostname": "nas.example.test", "user": "admin", "token": "x"}).text
    assert 'principals=&#34;tentaclai-nas&#34;' in html or 'principals="tentaclai-nas"' in html
    assert "as admin" in html and "as root" in html and 'id="man-key" hidden' in html
