"""svc ssh: commands or a shell on an SSH host, per-host access."""
import re
import subprocess
import sys
import shlex

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import core, docker_part, gate, safeguards


# ---------- ssh ----------

# Read-only commands that `svc ssh` runs without approval (also on read hosts): status only, no file contents
# (cat/grep could read a host's .env – those need approval). No shell syntax: one plain command, checked word by word.
SSH_READ = {"uptime", "df", "free", "ps", "ls", "hostname", "whoami", "id", "uname", "date", "lsblk", "findmnt",
            "nproc", "lscpu", "vmstat", "iostat", "who", "w", "last", "docker", "systemctl", "journalctl", "ip", "ss"}
SSH_SHELL_CHARS = set(";&|$`<>(){}\\\n")
SYSTEMCTL_READ = {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers",
                  "list-sockets", "list-dependencies", "show", "cat", "--failed"}
SYSTEMCTL_FLAGS = {"--no-pager", "--all", "-a", "--full", "-l", "--plain", "--no-legend", "--user", "--system", "--failed",
                   "-q", "--quiet", "--no-ask-password"}
DATE_FLAGS = {"-u", "--utc", "--universal", "-R", "--rfc-email", "-I", "--debug"}
HOSTNAME_FLAGS = {"-f", "--fqdn", "--long", "-s", "--short", "-d", "--domain", "-i", "--ip-address", "-I",
                  "--all-ip-addresses", "-A", "--all-fqdns", "-a", "--alias", "-y", "--yp", "--nis"}
IP_OPTION = re.compile(r"-{1,2}(4|6|s|stats|statistics|d|details|br|brief|j|json|p|pretty|o|oneline|h|human|r|resolve|"
                       r"c|color|colour)(=(always|auto|never))?")
JOURNAL_WRITE = ("--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--smart-relinquish", "--setup-keys",
                 "--update-catalog")


def ssh_read_only(alias, cmd):
    """True for a plain status command from SSH_READ (optionally behind the host's sudo prefix)"""
    text = ssh_remote(cmd)  # exactly what the remote shell gets
    if not cmd or any(c in SSH_SHELL_CHARS for c in text):
        return False
    try:
        words = shlex.split(text)
    except ValueError:
        return False
    sudo = shlex.split(core.ssh_sudo(alias) or "")
    if sudo and words[:len(sudo)] == sudo:
        words = words[len(sudo):]
    if not words or words[0] not in SSH_READ:
        return False
    head, rest = words[0], words[1:]
    args = [a for a in rest if not a.startswith("-")]
    if head == "docker":
        return bool(args) and docker_part._ro_allowed(rest)
    if head == "systemctl":
        # options before the verb only without a separate value: in `-p status restart x` the verb is restart
        verb = next((a for a in rest if not a.startswith("-")), None)
        before = rest[:rest.index(verb)] if verb else rest
        if not all(a in SYSTEMCTL_FLAGS or a.startswith("--") and "=" in a for a in before):
            return False
        return verb in SYSTEMCTL_READ if verb else "--failed" in rest
    if head == "date":  # a time or -s/--set sets the clock
        return all(a.startswith("+") or a in DATE_FLAGS or a.startswith(("--iso-8601", "--rfc-3339=")) for a in rest)
    if head == "hostname":  # a name, -F or -b sets it
        return all(a in HOSTNAME_FLAGS for a in rest)
    if head == "journalctl":
        return not any(a.startswith(JOURNAL_WRITE) for a in rest)
    if head == "ip":
        if any(a.startswith("-") and not IP_OPTION.fullmatch(a) for a in rest):  # -batch reads commands from a file
            return False
        return not args or args[0] in ("a", "addr", "address", "r", "route", "l", "link", "n", "neigh") and \
            not any(a in ("add", "del", "delete", "set", "change", "replace", "flush", "append", "restore") for a in args[1:])
    if head == "ps":  # BSD-style e (ps e, ps auxe) prints every process's environment – tokens included
        return not any("e" in a for a in args)
    if head == "ss":
        return not any(a in ("-K", "--kill") or (a.startswith("-") and not a.startswith("--") and "K" in a) for a in rest)
    return True


def cmd_ssh(name_args):
    """a command (or an interactive shell) on an SSH host – the key stays with svc; access per host (default confirm)"""
    if not name_args:
        print(f"{'Host':<16}{'Access':<9}{'User':<10}{'Hostname':<30}sudo")
        for h in tclib.ssh_hosts(core.SSH_CONF_D):
            print(f"{h['alias']:<16}{tclib.ssh_access(core.SSH_CONF_D, h['alias']):<9}{h['user'] or '–':<10}{h['hostname'] or '–':<30}{h['sudo'] or '–'}")
        return 0
    alias, cmd = name_args[0], name_args[1:]
    if cmd[:1] == ["--"]:
        cmd = cmd[1:]
    if not tclib.ssh_host(core.SSH_CONF_D, alias):
        sys.exit(f"svc: unknown SSH host '{alias}' (svc ssh)")
    gate.require_allowed(alias)
    mode = "read" if core.job_read_only() else tclib.ssh_access(core.SSH_CONF_D, alias)
    remote = ssh_remote(cmd)
    tty = not cmd or sys.stdin.isatty() and sys.stdout.isatty()
    argv = ["ssh"] + (["-t"] if tty else ["-T"]) + ["--", alias] + ([remote] if remote else [])
    if ssh_read_only(alias, cmd):  # free status command – the ones that print secrets get them blanked
        words = shlex.split(remote)
        sudo = shlex.split(core.ssh_sudo(alias) or "")
        if sudo and words[:len(sudo)] == sudo:
            words = words[len(sudo):]
        if safeguards.sensitive_read(words):
            return ssh_hint(safeguards.call_redacted(["ssh", "-T", "--", alias, remote]), alias, cmd)
        return ssh_hint(subprocess.call(argv), alias, cmd)
    return gate.guarded(alias, "ssh", mode, f"ssh {remote}" if remote else "ssh (interactive shell)",
                   lambda: ssh_hint(subprocess.call(argv), alias, cmd), interactive=tty)


SSH_WORD = re.compile(r"[\s|&;<>()]")


def ssh_remote(cmd):
    """the remote command line: one argument is a command line for the remote shell; of several, one holding spaces or
    | & ; < > ( ) was quoted locally – it stays one word over there (ssh would join them and the remote shell split it
    again: --format '{{.Names}} {{.Status}}' or 'a|b' broke)"""
    if len(cmd) == 1:
        return cmd[0]
    return " ".join(shlex.quote(a) if SSH_WORD.search(a) else a for a in cmd)


def ssh_hint(code, alias, cmd):
    """after a failed command with one-string syntax: a pattern the remote shell read as syntax is the usual cause"""
    if code in (0, 255) or len(cmd) != 1:
        return code
    bare = re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", "", cmd[0])
    if "{{" in bare or re.search(r"(?<![|])\|(?![|])", bare):
        print(f"svc: the remote command failed (exit {code}) – if `|` or `{{{{…}}}}` was meant as a pattern, the remote shell "
              f"read it as syntax: put it in single quotes inside, e.g. svc ssh {alias} \"grep -E 'a|b' /path\"; "
              f"containers: svc docker {alias} ps", file=sys.stderr)
    return code


SYSTEM_KEYS = {"_help", "name", "description", "ssh_host", "notes"}


REVIEW_DIFF = 4000  # characters of the diff shown with the approval
