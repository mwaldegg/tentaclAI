"""svc docker / svc compose: the Docker CLI against a host over SSH, read-only checks for access read."""
import os
import re
import subprocess
import sys
import shlex

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import core, gate, safeguards


# ---------- docker ----------


def docker_sudo(d):
    return core.ssh_sudo(d["ssh_host"])


def docker_target(d, md=False):
    """where a docker service runs docker: always over ssh (this host too, via host.docker.internal)"""
    host = f"`{d.get('ssh_host')}`" if md else d.get("ssh_host")
    return f"ssh {host}" + (" (sudo)" if core.ssh_sudo(d.get("ssh_host", "")) else "")


def wants_tty(args, compose=False):
    """interactive call from a terminal (docker exec/run -it, compose exec/run without -T) → ssh must allocate one"""
    if not sys.stdin.isatty():
        return False
    words = [a for a in args if not a.startswith("-")]
    if compose:
        return bool(words) and words[0] in ("exec", "run") and "-T" not in args and "--no-TTY" not in args
    flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    return bool(words) and words[0] in ("exec", "run", "attach") and ("t" in flags or "--tty" in args)


def docker_argv(name, d, args):
    """docker CLI for a docker service: runs on the host through ssh – local files are never touched"""
    sudo = docker_sudo(d)
    return ["ssh"] + (["-t", "-q"] if wants_tty(args) else []) + [d["ssh_host"], f"{sudo + ' ' if sudo else ''}docker {shlex.join(args)}"]


def docker_services(services, usable=True):
    out = {}
    for n, s in services.items():
        if "docker" in s and (not usable or (core.enabled(s) and not core.missing_vars(s["docker"]))):
            out[n] = s
    return out


# global options a read may carry before the command (anything else – -H, --config, -f … – needs approval)
RO_GLOBAL_DOCKER = ({"-D", "--debug", "-v", "--version", "--help"}, {"-l", "--log-level"})
RO_GLOBAL_COMPOSE = ({"--dry-run", "--compatibility", "--all-resources", "-v", "--version", "--help"},
                     {"-p", "--project-name", "--profile", "--ansi", "--progress", "--parallel"})


def _ro_allowed(args, compose=False):
    flags, values = RO_GLOBAL_COMPOSE if compose else RO_GLOBAL_DOCKER
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a in values:
            i += 2
        elif a in flags or a.split("=", 1)[0] in values and "=" in a:
            i += 1
        else:
            return False
    words = args[i:]
    if not words:
        return True
    if compose:
        return words[0] in core.RO_COMPOSE
    if words[0] not in core.RO_DOCKER:
        return False
    if words[0] in ("network", "volume", "image", "container", "system", "context"):
        return len(words) > 1 and words[1] in core.RO_SUB
    return True


def get_docker(services, name):
    svc = gate.get(services, name)
    if "docker" not in svc:
        sys.exit(f"svc: {name} is not a docker service (svc docker)")
    if not core.enabled(svc):
        sys.exit(f"svc: {name} is disabled")
    miss = core.missing_vars(svc["docker"])
    if miss:
        sys.exit(f"svc: {name} not enabled – empty in .env: {', '.join(miss)}")
    d = core.render(svc["docker"])
    if d.get("mode", "ssh") != "ssh" or not d.get("ssh_host"):
        sys.exit(f"svc: {name}: docker services run over SSH only – set \"mode\": \"ssh\" and \"ssh_host\" "
                 "(this host: an SSH host for host.docker.internal)")
    return d


def cmd_docker(services, args):
    if not args:
        ds = docker_services(services, usable=False)
        if not ds:
            print("No docker services.")
            return 0
        print(f"{'Name':<16}{'Access':<9}{'Target':<34}Stacks")
        for n, s in ds.items():
            d = core.render(s["docker"])
            st = core.status(s)
            print(f"{n:<16}{tclib.access(d.get('access')):<9}{docker_target(d):<34}{d.get('stacks_dir', '–')}"
                  + ("" if st == "active" else f"  ({st})"))
        return 0
    name, rest = args[0], args[1:]
    d = get_docker(services, name)
    call = safeguards.call_redacted if safeguards.sensitive_read(rest) else subprocess.call
    run = lambda: call(docker_argv(name, d, rest))  # noqa: E731
    if _ro_allowed(rest):
        return run()
    return gate.guarded(name, "docker", gate.access_mode(d), "docker " + shlex.join(rest), run, interactive=wants_tty(rest))


def cmd_compose(services, name, stack, rest):
    d = get_docker(services, name)
    if _ro_allowed(rest, compose=True):
        return _compose(name, d, stack, rest)
    return gate.guarded(name, "docker", gate.access_mode(d), f"compose {stack} {shlex.join(rest)}",
                   lambda: _compose(name, d, stack, rest), interactive=wants_tty(rest, compose=True))


def _compose(name, d, stack, rest):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", stack):
        sys.exit("svc: invalid stack name")
    base = d.get("stacks_dir") or sys.exit(f"svc: {name} has no stacks_dir")
    path = os.path.join(base, stack)
    sudo = docker_sudo(d)
    remote = f"cd {shlex.quote(path)} && {sudo + ' ' if sudo else ''}docker compose {shlex.join(rest)}"
    if safeguards.sensitive_read(rest, compose=True):
        return safeguards.call_redacted(["ssh", "-q", d["ssh_host"], remote])
    return subprocess.call(["ssh"] + (["-t", "-q"] if wants_tty(rest, compose=True) else []) + [d["ssh_host"], remote])
