"""SSH host operations that run inside the sandbox: fetch/confirm host keys, deploy the key with a one-time
password, remove it again, and keep references (services, systems) in sync when an alias changes."""
import json
import secrets
import time

import shlex

import tclib

from . import dockerops, services_store, sshca, sshhosts, systems_store

_PENDING = {}  # token -> scanned host key, valid for 10 minutes
SSH_BASE = ["-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=10"]


def _target_args(f):
    args = ["-p", str(f.get("port") or "22")]
    if f.get("hostkeyalias"):
        args += ["-o", f"HostKeyAlias={f['hostkeyalias']}"]
    if f.get("proxyjump"):
        args += ["-J", f["proxyjump"]]
    return args + [f"{f['user']}@{f['hostname']}"]


def scan(fields):
    """connect without authenticating and collect the host key; returns dict with token, fingerprints – or raises"""
    # the temporary known_hosts file only exists in the shell, so its option lives in the script
    script = ('t=$(mktemp); ssh -o UserKnownHostsFile="$t" "$@" true >/dev/null 2>"$t.err"; '
              'if [ -s "$t" ]; then echo "##KEYS"; cat "$t"; echo "##FP"; ssh-keygen -lf "$t"; '
              'else echo "##ERR"; grep -v "^Warning: Permanently" "$t.err" | tail -3; fi; rm -f "$t" "$t.err"')
    args = SSH_BASE + ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "GlobalKnownHostsFile=/dev/null",
                       "-o", "HashKnownHosts=no", "-o", "PreferredAuthentications=none"]
    code, out = dockerops.sandbox_exec(["bash", "-c", script, "scan"] + args + _target_args(fields), timeout=40)
    if "##KEYS" not in out:
        err = out.split("##ERR", 1)[-1].strip() or "no answer"
        raise RuntimeError(f"could not fetch the host key: {err[-300:]}")
    keys, fps = out.split("##KEYS", 1)[1].split("##FP", 1)
    lines = [l for l in keys.strip().splitlines() if l.strip()]
    fps = [l.strip() for l in fps.strip().splitlines() if l.strip()]
    token = secrets.token_urlsafe(16)
    for k in [k for k, v in _PENDING.items() if time.time() - v["ts"] > 600]:
        _PENDING.pop(k, None)
    _PENDING[token] = {"name": sshhosts.known_name(fields), "lines": lines, "ts": time.time()}
    return {"token": token, "fingerprints": fps, "name": sshhosts.known_name(fields)}


def trust(token):
    """store a confirmed host key in ssh/known_hosts (replacing old entries for that name)"""
    p = _PENDING.pop(token, None)
    if not p or time.time() - p["ts"] > 600:
        raise RuntimeError("host key check expired – please fetch the key again")
    code, out = dockerops.sandbox_exec(
        ["bash", "-c", 'ssh-keygen -R "$1" -f ~/.ssh/known_hosts >/dev/null 2>&1; cat >> ~/.ssh/known_hosts; rm -f ~/.ssh/known_hosts.old',
         "trust", p["name"]], stdin="\n".join(p["lines"]) + "\n", timeout=20)
    if code != 0:
        raise RuntimeError(f"could not store the host key: {out.strip()[-200:]}")


def deploy(fields, password, cert=False):
    """append the public key – or with cert the CA line for the host's principal – on the target, logging in once with
    a password (passed via stdin, never stored)"""
    if cert:
        pub = sshca.authorized_line(tclib.ssh_principal(fields))
    else:
        pub = sshhosts.public_key()
        if not pub:
            raise RuntimeError("public key ssh/keys/tentaclai_ed25519.pub missing")
    body = pub.split()[-2]
    remote = ("umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
              f"grep -qF '{body}' ~/.ssh/authorized_keys && echo TC_ALREADY || "
              f"{{ echo '{pub}' >> ~/.ssh/authorized_keys && echo TC_ADDED; }}")
    args = SSH_BASE + ["-n", "-o", "StrictHostKeyChecking=yes", "-o", "PubkeyAuthentication=no",
                       "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1"]
    code, out = dockerops.sandbox_exec(["sshpass", "-f", "/dev/stdin", "ssh"] + args + _target_args(fields) + [remote],
                                       stdin=password + "\n", timeout=40)
    if "TC_ADDED" in out:
        return "added"
    if "TC_ALREADY" in out:
        return "already"
    reason = {5: "wrong password", 6: "host key not confirmed"}.get(code) or (out.strip().splitlines() or ["login failed"])[-1]
    raise RuntimeError(f"could not deploy the key: {reason}")


def _key_body():
    pub = sshhosts.public_key() or ""
    return pub.split()[1] if len(pub.split()) > 1 else ""


def _ca_body():
    return sshca.public_line().split()[1]


def _on_host(alias, remote, marker):
    """run one of our own scripts on the host as tentaclAI (key or certificate, whatever the host uses now)"""
    code, out = dockerops.sandbox_exec(["ssh", "-o", "BatchMode=yes"] + SSH_BASE + [alias, remote], timeout=40)
    if marker not in out:
        raise RuntimeError((out.strip().splitlines() or ["ssh failed"])[-1][:200])
    return out


def unauthorize(alias, key=True, ca=True):
    """remove tentaclAI's key and/or the CA line from the target (logs in one last time)"""
    bodies = ([_key_body()] if key else []) + ([_ca_body()] if ca and sshca.available() else [])
    bodies = [b for b in bodies if b]
    if not bodies:
        raise RuntimeError("public key missing")
    _on_host(alias, unauthorize_script(bodies), "TC_REMOVED")


def unauthorize_script(bodies):
    pats = " ".join(f"-e {shlex.quote(b)}" for b in bodies)
    return (f"f=~/.ssh/authorized_keys; [ -f $f ] || {{ echo TC_REMOVED; exit 0; }}; "
            f"grep -vF {pats} $f > $f.tc; cat $f.tc > $f; rm -f $f.tc; echo TC_REMOVED")


# the options of an existing line (from="…", command=…) are carried over to the line that replaces it – a restriction
# set up for tentaclAI's key stays in place for its certificates and back. Values reach the remote shell only as
# quoted assignments (shlex.quote); the scripts use plain sh, grep and sed.
_KEY_OPTS = r"s/^\(.*[^ ]\)  *ssh-ed25519 [^ ]*.*/\1/p"            # options before the key, if any
_CA_OPTS = r"s/^cert-authority,principals=[^, ]*,\(.*[^ ]\)  *ssh-ed25519 .*/\1/p"  # options after the principal


def install_ca_script(key_body, ca_line, principal):
    """the script that puts the CA line on a host: drop an older CA line, keep the key line's options"""
    if not tclib.PRINCIPAL_RE.match(principal):
        raise RuntimeError("bad principal")
    return (f"umask 077; mkdir -p ~/.ssh; f=~/.ssh/authorized_keys; touch $f; "
            f"k={shlex.quote(key_body or '-none-')}; c={shlex.quote(ca_line.split()[1])}; ca={shlex.quote(ca_line)}; "
            f"p={shlex.quote(principal)}; "
            f"o=$(grep -F -e \"$k\" $f | sed -n {shlex.quote(_KEY_OPTS)} | head -1); "
            f"grep -vF -e \"$c\" $f > $f.tc; cat $f.tc > $f; rm -f $f.tc; "
            "printf 'cert-authority,principals=\"%s\"%s %s\\n' \"$p\" \"${o:+,$o}\" \"$ca\" >> $f; echo TC_CA_ADDED")


def install_key_script(pub, ca_body):
    """the script that puts tentaclAI's key back on a host, with the CA line's options"""
    return (f"umask 077; mkdir -p ~/.ssh; f=~/.ssh/authorized_keys; touch $f; "
            f"c={shlex.quote(ca_body)}; pub={shlex.quote(pub)}; k={shlex.quote(pub.split()[1])}; "
            f"o=$(grep -F -e \"$c\" $f | sed -n {shlex.quote(_CA_OPTS)} | head -1); "
            "grep -qF -e \"$k\" $f || printf '%s%s\\n' \"${o:+$o }\" \"$pub\" >> $f; echo TC_KEY_ADDED")


def install_ca(alias, principal):
    """put the CA line for this principal on the host (replacing an older one); logs in as the host is set up now"""
    _on_host(alias, install_ca_script(_key_body(), sshca.public_line(), principal), "TC_CA_ADDED")


def install_key(alias):
    """put tentaclAI's key back on the host (switching back from certificates)"""
    pub = sshhosts.public_key()
    if not pub:
        raise RuntimeError("public key ssh/keys/tentaclai_ed25519.pub missing")
    _on_host(alias, install_key_script(pub, _ca_body()), "TC_KEY_ADDED")


def manual_commands(user, line):
    """(who, command) to put one line into the user's authorized_keys by hand: as the user, and – for another user –
    as root"""
    q = shlex.quote(line)
    own = (f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo {q} >> ~/.ssh/authorized_keys && "
           "chmod 600 ~/.ssh/authorized_keys")
    cmds = [(f"as {user}", own)]
    if user != "root" and tclib.USER_RE.match(user or ""):
        h = f"$(getent passwd {user} | cut -d: -f6)"
        cmds.append(("as root", f"h={h} && install -d -m 700 -o {user} \"$h/.ssh\" && echo {q} >> \"$h/.ssh/authorized_keys\" && "
                                f"chown {user} \"$h/.ssh/authorized_keys\" && chmod 600 \"$h/.ssh/authorized_keys\""))
    return cmds


def cert_login(alias):
    """(ok, last line): does the host take tentaclAI's certificate? A fresh connection with ssh -v – ok only when the
    server accepted the certificate (not the key)"""
    code, out = dockerops.sandbox_exec(["ssh", "-v", "-o", "BatchMode=yes"] + SSH_BASE + [alias, "true"], timeout=40)
    accepted = any("Server accepts key:" in l and "-CERT" in l for l in out.splitlines())
    errors = [l for l in out.splitlines() if l.strip() and not l.startswith("debug")]
    return code == 0 and accepted, (errors[-1] if errors else "the host did not accept the certificate")[:200]


def references(alias):
    """services, systems and other SSH hosts (ProxyJump) that use this SSH host"""
    refs = [("host", h["alias"]) for h in sshhosts.hosts() if h.get("proxyjump") == alias]
    for s in services_store.load_all():
        d = s["data"]
        if (d.get("docker") or {}).get("ssh_host") == alias or (d.get("files") or {}).get("ssh_host") == alias:
            refs.append(("service", s["name"]))
    for x in systems_store.load_all():
        if x.get("ssh_host") == alias:
            refs.append(("system", x["name"]))
    return refs


def rename_references(old, new):
    for kind, name in references(old):
        if kind == "host":
            h = sshhosts.get(name)
            sshhosts.update(name, dict(h, proxyjump=new))
        elif kind == "service":
            data = json.loads(services_store.read_raw(name))
            for part in ("docker", "files"):
                if (data.get(part) or {}).get("ssh_host") == old:
                    data[part]["ssh_host"] = new
            services_store.save_raw(name, json.dumps(data, ensure_ascii=False))
        else:
            x = systems_store.get(name)
            members = [s["name"] for s in services_store.load_all() if s["data"].get("system") == name]
            systems_store.save(name, x.get("description", ""), new, x.get("notes", []), members)
