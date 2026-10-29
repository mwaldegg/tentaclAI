"""svc's command line: parsing the arguments and dispatching to the parts."""
import json
import os
import sys
import time
import shlex

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import (api_part, catalog, config_part, core, db_part, docker_part, files_part, gate, git_part, jobs_part,
    mail_part, mcp_part, safeguards, ssh_part, web_part)

USAGE = __doc__  # the usage is the docstring of the entry point build/svc, which hands it to cli()


def cmd_rc_env():
    """the remote-control settings (no secrets) for rc-loop, which runs as Claude and can't read .env"""
    env = tclib.read_env(core.ENV_FILE)
    for k in ("RC_ENABLED", "RC_NAME", "RC_WORKDIR", "RC_EXTRA_ARGS", "RC_RESTART_DELAY"):
        if k in env:
            print(f"{k}={shlex.quote(env[k])}")
    return 0


def main(argv):
    core.elevate()
    try:
        core.ORIG_CWD = os.getcwd()
    except OSError:
        core.ORIG_CWD = "/"
    if core.privileged():
        os.chdir("/")  # nothing running as root reads files from Claude's current directory
    if argv[1:2] == ["origin-of"] and len(argv) == 3:
        return cmd_origin_of(argv[2])  # before .env and the services are loaded – a /proc lookup needs neither
    core.load_env_file()
    services = core.load()
    SERVICE_NAMES.update(services)
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(USAGE.strip())
        return 0
    cmd = argv[1]
    if cmd == "list":
        return catalog.cmd_list(services)
    if cmd in ("systems", "system"):
        return catalog.cmd_systems(services, argv[2] if len(argv) > 2 else None)
    if cmd == "info" and len(argv) == 4 and argv[3] == "--json":
        return catalog.cmd_info_json(services, argv[2])
    if cmd == "info" and len(argv) == 3:
        return catalog.cmd_info(services, argv[2])
    if cmd == "sync":
        return catalog.cmd_sync(services)
    if cmd == "git":
        if len(argv) >= 3 and argv[2] == "sync":
            return git_part.git_sync(services, argv[3:] or None)
        if len(argv) >= 4 and argv[2] in ("fetch", "pull"):
            return git_part.cmd_git_fetch(services, argv[3], pull=argv[2] == "pull")
        if len(argv) >= 4 and argv[2] == "push":
            return git_part.cmd_git_push(services, argv[3], argv[4:])
        return git_part.cmd_git_list(services)
    if cmd == "ssh":
        return ssh_part.cmd_ssh(argv[2:])
    if cmd == "mcp-proxy" and len(argv) == 3:
        return mcp_part.cmd_mcp_proxy(services, argv[2])
    if cmd == "rc-env":
        return cmd_rc_env()
    if cmd == "pending":
        return gate.cmd_pending(argv[2:])
    if cmd == "config":
        return config_part.cmd_config(services, argv[2:])
    if cmd == "docker":
        return docker_part.cmd_docker(services, argv[2:])
    if cmd == "test" and len(argv) == 3:
        return catalog.cmd_test(services, argv[2])
    if cmd == "audit":
        return gate.cmd_audit(argv[2:])
    if cmd == "git-push-hook" and len(argv) >= 3:
        return git_part.git_push_hook(services, argv[2], argv[3:])
    if cmd == "db":
        return db_part.cmd_db(services, argv[2:])
    if cmd == "jobs":
        return jobs_part.cmd_jobs(argv[2:])
    if cmd == "tool-report":
        return safeguards.cmd_tool_report(argv[2:], services)
    if cmd == "mail":
        return mail_part.cmd_mail(services, argv[2:])
    if cmd == "web":
        return web_part.cmd_web(services, argv[2:])
    if cmd == "files":
        return files_part.cmd_files(services, argv[2:])
    if cmd == "compose" and len(argv) >= 5:
        return docker_part.cmd_compose(services, argv[2], argv[3], argv[4:])
    if cmd == "git-credential" and len(argv) >= 4:
        return git_part.cmd_git_credential(services, argv[2], argv[3])
    if len(argv) >= 4:
        return api_part.cmd_call(services, argv[1], argv[2], argv[3], argv[4:])
    print(USAGE.strip())
    return 1


def cmd_origin_of(port):
    """tentacontrol (root, never through sudo): which process of the sandbox holds the connection from local port
    <port> – asked while the egress gateway holds a connection to an unknown destination → JSON {command, user, origin}"""
    if not core.privileged() or core.via_sudo():
        sys.exit("svc: origin-of is for tentacontrol only")
    if not port.isdigit() or not 0 < int(port) < 65536:
        sys.exit("svc: origin-of <port>")
    found, res = core.port_socket(int(port)), {}
    if found:  # looked up as the socket's owner: only it may read its processes' fds and environment
        inode, uid = found

        def lookup():
            pid = core.socket_pid(inode)
            return core.process_origin(pid) if pid else {}
        res = core.as_uid(uid, lookup) or {}
    print(json.dumps(res))
    return 0


SERVICE_NAMES = set()
NOT_LOGGED = {"-h", "--help", "help", "pending", "audit", "tool-report", "mcp-proxy", "origin-of", "git-credential",
              "git-push-hook", "rc-env"}  # svc's own plumbing and lookups – no audit entry
ROOT_LOGGED = {"sync", "git"}  # run by tentacontrol or the entrypoint: only these get an entry (pages poll the rest – svc test
# for the status dots too; the Test button is an admin action of its own)


def read_entry(argv, rc, seconds):
    """the audit entry of a call that wrote none itself (a read): "read", with the command line, exit code and time"""
    if gate.AUDITED or len(argv) < 2 or argv[1] in NOT_LOGGED or (core.privileged() and not core.via_sudo() and argv[1] not in ROOT_LOGGED):
        return
    if argv[1] == "ssh":
        name = argv[2] if len(argv) > 2 else ""
    else:
        name = argv[1] if argv[1] in SERVICE_NAMES else next((a for a in argv[2:] if a in SERVICE_NAMES), "")
    part = argv[1] if argv[1] in tclib.PARTS or argv[1] in ("ssh", "test", "sync", "jobs", "config") else \
        "api" if name == argv[1] else argv[1][:20]
    rest = argv[1:]
    if name in rest:  # the target has its own field – the action is the rest of the command line
        rest.remove(name)
    action = safeguards._redact_text(" ".join(rest))[:500]
    gate.audit(name or "svc", part, "read", action, "read", rc=rc, duration=seconds)


def run(argv):
    t, rc = time.time(), 1
    try:
        rc = main(argv) or 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        raise
    finally:
        try:
            read_entry(argv, rc, time.time() - t)
        except Exception:  # noqa: BLE001 – the audit never fails a command
            pass
    return rc


def cli(argv, usage=None):
    global USAGE
    USAGE = usage or USAGE
    try:
        return run(argv)
    except BrokenPipeError:  # output piped into head & co., which stopped reading – end quietly like other CLI tools
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())  # no second error when Python flushes at exit
        return 141  # 128 + SIGPIPE, what the shell reports for a tool killed by the closed pipe


if __name__ == "__main__":
    sys.exit(cli(sys.argv))
