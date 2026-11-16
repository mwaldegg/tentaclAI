"""tentaclAI's SSH certificate authority: hosts with login "cert" trust its public key for one principal
(a cert-authority line in authorized_keys); every connection from the sandbox gets a short-lived certificate for a
fresh key pair (tc-cert → /internal/ssh-cert). The CA key lives in a volume only tentacontrol mounts (SSH_CA_DIR) – the
sandbox sees the stack directory, so a key in data/ would be readable by root there."""
import os
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import ssh as sshformat
from cryptography.hazmat.primitives.asymmetric import ed25519

import tclib

from . import auditlog, jsonstore, log, sshhosts
from .envfile import read_env

CA_DIR = os.environ.get("SSH_CA_DIR", "/ssh-ca")
MINUTES_DEFAULT, MINUTES_MAX = 5, 60
_LOCK = threading.Lock()
_log = log.get("ssh")


def _key_path():
    return os.path.join(CA_DIR, "ca_ed25519")


def _load():
    """the CA's private key – created on first use"""
    with _LOCK:
        path = _key_path()
        if not os.path.exists(path):
            os.makedirs(CA_DIR, mode=0o700, exist_ok=True)
            key = ed25519.Ed25519PrivateKey.generate()
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                    serialization.NoEncryption())
            fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            os.replace(path + ".tmp", path)
            _log.info("SSH CA key created")
        with open(path, "rb") as f:
            return serialization.load_ssh_private_key(f.read(), password=None)


def available():
    """whether the CA's directory can hold a key (the volume is mounted) – the SSH page explains it otherwise"""
    return os.path.isdir(CA_DIR) and os.access(CA_DIR, os.W_OK)


def public_line():
    """the CA's public key as an OpenSSH line"""
    pub = _load().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    name = read_env().get("TC_HOSTNAME") or "tentaclai"
    return f"{pub.decode()} tentaclai-ca@{name}"


def authorized_line(principal, options=""):
    """the line a host puts in authorized_keys to trust the CA for this principal only (plus the old key's options,
    e.g. from=…)"""
    if not tclib.PRINCIPAL_RE.match(principal):
        raise ValueError("bad principal")
    opts = f'cert-authority,principals="{principal}"' + (f",{options}" if options else "")
    return f"{opts} {public_line()}"


def minutes():
    try:
        m = int(read_env().get("SSH_CERT_MINUTES") or MINUTES_DEFAULT)
    except ValueError:
        m = MINUTES_DEFAULT
    return max(1, min(MINUTES_MAX, m))


def _serial():
    path = os.path.join(CA_DIR, "serial.json")
    with jsonstore.locked(path):
        n = int(jsonstore.load(path, {}).get("next") or 1)
        jsonstore.save(path, {"next": n + 1})
    return n


def issue(alias, public_key, origin=None):
    """a certificate for this host's principal on the given public key (ed25519, OpenSSH line) → (certificate line,
    valid_before). Only for a host with login "cert"; every certificate goes into the audit log"""
    h = sshhosts.get(alias)
    if not h or h.get("auth") != "cert":
        raise ValueError(f"{alias} does not log in with certificates")
    try:
        key = serialization.load_ssh_public_key(str(public_key).strip().encode())
    except (ValueError, TypeError):
        raise ValueError("not an OpenSSH public key")
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("only ed25519 keys are signed")
    principal = tclib.ssh_principal(h)
    now = int(time.time())
    before = now + minutes() * 60
    serial = _serial()
    key_id = f"tentaclai {alias} #{serial}"
    cert = (sshformat.SSHCertificateBuilder()
            .public_key(key)
            .serial(serial)
            .type(sshformat.SSHCertificateType.USER)
            .key_id(key_id.encode())
            .valid_principals([principal.encode()])
            .valid_after(now - 60)  # a host clock a little behind still accepts it
            .valid_before(before)
            .add_extension(b"permit-pty", b"")
            .sign(_load()))
    line = cert.public_bytes().decode() + f" {key_id}"
    auditlog.write("system", alias, f"SSH certificate #{serial} for {principal}, valid {minutes()} min", "ok",
                   actor="system", part="ssh", origin=origin, detail=key_id)
    return line, before
