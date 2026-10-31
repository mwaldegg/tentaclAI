"""svc git: repositories (clone, fetch, pull, push), the credential helper and the pre-push hook."""
import os
import re
import shutil
import subprocess
import sys
import shlex

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import core, gate


# ---------- git ----------
# The working copy belongs to Claude (/workspace/repos/<name>) and has no credentials. svc keeps a bare mirror per
# repo (root only, ~/.cache/tentaclai/git) that talks to the remote; commits travel between the two as git bundles.
# Root never runs git inside Claude's repo (its config and hooks could run commands), Claude never sees a token.


def repo_path(name, git):
    return git.get("path") or os.path.join(core.REPO_ROOT, name)


def git_run(args, cwd="/", quiet=False):
    """git as root – only for the mirror and remote URLs, never in Claude's working copy"""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SUDO_", "GIT_"))}
    env["GIT_TERMINAL_PROMPT"] = "0"
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True)
    if r.returncode != 0 and not quiet:
        print(f"    git {' '.join(a for a in args[:3] if not a.startswith('credential'))}: {(r.stderr or r.stdout).strip()[:300]}")
    return r


def claude_git(args, path, quiet=False):
    """git as Claude in the working copy"""
    r = subprocess.run(["git", *args], capture_output=True, text=True, **core.as_user(core.CLAUDE_USER, {"GIT_TERMINAL_PROMPT": "0"}, cwd=path))
    if r.returncode != 0 and not quiet:
        print(f"    git {' '.join(args[:2])}: {(r.stderr or r.stdout).strip()[:300]}")
    return r


def uses_token(git):
    return (git.get("auth") or {}).get("type") == "token"


def remote_args(name, git):
    args = ["-c", "credential.helper="] + (["-c", "http.sslVerify=false"] if git.get("insecure_tls") else [])
    if uses_token(git):
        args += ["-c", f"credential.helper=!{os.path.abspath(sys.argv[0])} git-credential {name}"]
    return args


def mirror_path(name):
    return os.path.join(core.MIRRORS, f"{name}.git")


def mirror_fetch(name, git):
    """create/refresh the bare mirror; returns the default branch or None on failure"""
    m = mirror_path(name)
    if not os.path.isdir(m):
        os.makedirs(core.MIRRORS, mode=0o700, exist_ok=True)
        if git_run(["init", "--quiet", "--bare", m]).returncode != 0:
            return None
        git_run(["config", "remote.origin.url", git["url"]], cwd=m)
        git_run(["config", "--add", "remote.origin.fetch", "+refs/heads/*:refs/heads/*"], cwd=m)
        git_run(["config", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*"], cwd=m)
    else:
        git_run(["config", "remote.origin.url", git["url"]], cwd=m)
    if git_run(remote_args(name, git) + ["fetch", "--quiet", "--prune", "origin"], cwd=m).returncode != 0:
        return None
    branch = git.get("branch")
    if not branch:
        r = git_run(remote_args(name, git) + ["ls-remote", "--symref", "origin", "HEAD"], cwd=m, quiet=True)
        found = re.search(r"^ref: refs/heads/(\S+)\s+HEAD", r.stdout, re.M)
        branch = found.group(1) if found else "main"
    git_run(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=m, quiet=True)
    return branch


def bundle_to_claude(name, git, path):
    """mirror → Claude's working copy (clone if missing, else fetch into refs/remotes/origin)"""
    branch = mirror_fetch(name, git)
    if branch is None:
        return False
    m = mirror_path(name)
    if not git_run(["for-each-ref", "--count=1", "refs/heads"], cwd=m, quiet=True).stdout.strip():
        print(f"    {name}: remote repository is empty")
        return os.path.isdir(os.path.join(path, ".git")) or claude_git(["init", "--quiet", "-b", branch, path], "/").returncode == 0
    stage = core.stage_dir()
    try:
        b = os.path.join(stage, "repo.bundle")
        if git_run(["bundle", "create", "--quiet", b, "--all"], cwd=m).returncode != 0:
            return False
        core.give(stage, core.CLAUDE_USER)
        if not os.path.isdir(os.path.join(path, ".git")):
            parent = os.path.dirname(path)
            subprocess.run(["mkdir", "-p", parent], **core.as_user(core.CLAUDE_USER, cwd="/"))
            if claude_git(["clone", "--quiet", "--branch", branch, b, path], parent).returncode != 0:
                return False
            claude_git(["remote", "set-url", "origin", git["url"]], path)
            return True
        # --prune only for branches: with a tags refspec it would also delete local tags that were never pushed
        return (claude_git(["fetch", "--quiet", "--prune", b, "+refs/heads/*:refs/remotes/origin/*"], path).returncode == 0
                and claude_git(["fetch", "--quiet", b, "+refs/tags/*:refs/tags/*"], path).returncode == 0)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def configure_repo(name, path, git):
    """settings of the working copy (as Claude) – idempotent; drops credentials and pushurls of older versions"""
    claude_git(["config", "--unset-all", "credential.helper"], path, quiet=True)
    claude_git(["config", "--unset", "remote.origin.pushurl"], path, quiet=True)
    claude_git(["config", "tentaclai.service", name], path)
    claude_git(["config", "tentaclai.access", tclib.access(git.get("access"))], path)
    if git.get("insecure_tls"):
        claude_git(["config", "http.sslVerify", "false"], path)
    else:
        claude_git(["config", "--unset", "http.sslVerify"], path, quiet=True)
    author = tclib.git_author(git)
    if author:  # this repo's commit author – else GIT_USER_NAME/EMAIL (global)
        claude_git(["config", "user.name", author[0]], path)
        claude_git(["config", "user.email", author[1]], path)
        claude_git(["config", "tentaclai.author", "true"], path)
    elif claude_git(["config", "--get", "tentaclai.author"], path, quiet=True).returncode == 0:
        for key in ("user.name", "user.email", "tentaclai.author"):  # only what svc set itself
            claude_git(["config", "--unset", key], path, quiet=True)
    hook = os.path.join(path, ".git", "hooks", "pre-push")
    # plain `git push` has no credentials – the hook points to svc git push
    text = f"#!/bin/sh\n{core.HOOK_MARK}\nexec svc git-push-hook {shlex.quote(name)} \"$@\"\n"
    r = subprocess.run(["sh", "-c", 'grep -qsE "# tentaclai (read-only|pre-push) hook" "$1" || [ ! -e "$1" ] && '
                        '{ mkdir -p "$(dirname "$1")"; cat > "$1"; chmod 755 "$1"; }', "sh", hook],
                       input=text, text=True, **core.as_user(core.CLAUDE_USER, cwd="/"))
    if r.returncode != 0:
        print(f"    {name}: own pre-push hook kept", file=sys.stderr)


def git_sync(services, names=None, fetch=True):
    repos = {n: s for n, s in services.items() if "git" in s and (not names or n in names)}
    for name in names or []:
        if name not in repos:
            print(f"  ✗ {name}: not a git service")
    for name, svc in repos.items():
        git = svc["git"]
        if not core.enabled(svc):
            print(f"  – {name}: disabled")
            continue
        miss = core.missing_vars(git)
        if miss:
            print(f"  – {name}: skipped, empty in .env: {', '.join(miss)}")
            continue
        git = core.render(git)
        path = repo_path(name, git)
        if not os.path.isdir(os.path.join(path, ".git")):
            if not bundle_to_claude(name, git, path):
                print(f"  ✗ {name}: clone failed")
                continue
            configure_repo(name, path, git)
            print(f"  ✓ {name}: cloned to {path} ({tclib.access(git.get('access'))})")
            continue
        configure_repo(name, path, git)
        if fetch:
            ok = bundle_to_claude(name, git, path)
            print(f"  {'✓' if ok else '✗'} {name}: {'updated (fetch)' if ok else 'fetch failed'} – {tclib.access(git.get('access'))}")
        else:
            print(f"  ✓ {name}: present ({tclib.access(git.get('access'))})")


def git_state(path):
    if not os.path.isdir(os.path.join(path, ".git")):
        return "not cloned"
    branch = claude_git(["rev-parse", "--abbrev-ref", "HEAD"], path, quiet=True).stdout.strip()
    counts = claude_git(["rev-list", "--left-right", "--count", "HEAD...@{upstream}"], path, quiet=True).stdout.split()
    dirty = bool(claude_git(["status", "--porcelain"], path, quiet=True).stdout.strip())
    parts = [branch or "?"]
    if len(counts) == 2:
        if counts[0] != "0":
            parts.append(f"↑{counts[0]}")
        if counts[1] != "0":
            parts.append(f"↓{counts[1]}")
    if dirty:
        parts.append("changes")
    return " ".join(parts)


def cmd_git_list(services):
    repos = {n: s for n, s in services.items() if "git" in s}
    if not repos:
        print("No git services.")
        return
    print(f"{'Name':<18}{'Access':<9}{'Status':<28}Path")
    for name, svc in repos.items():
        git = svc["git"]
        path = repo_path(name, git)
        state = core.status(svc) if core.status(svc) != "active" else git_state(path)
        print(f"{name:<18}{tclib.access(git.get('access')):<9}{state:<28}{path}")


def get_git(services, name):
    svc = gate.get(services, name)
    if "git" not in svc:
        sys.exit(f"svc: {name} is not a git service (svc git)")
    git = gate.get_part(services, name, "git")
    path = repo_path(name, git)
    if not os.path.isdir(os.path.join(path, ".git")):
        sys.exit(f"svc: {name} is not cloned yet – svc git sync {name}")
    return git, path


def cmd_git_fetch(services, name, pull=False):
    git, path = get_git(services, name)
    if not bundle_to_claude(name, git, path):
        return 1
    print(f"✓ {name}: fetched")
    if pull:
        r = claude_git(["merge", "--ff-only", "@{upstream}"], path)
        print(r.stdout.strip() or r.stderr.strip())
        return r.returncode
    return 0


def cmd_git_push(services, name, args):
    git, path = get_git(services, name)
    force = any(a in ("-f", "--force") for a in args)
    rest = [a for a in args if a not in ("-f", "--force")]
    branch = rest[0] if rest else claude_git(["rev-parse", "--abbrev-ref", "HEAD"], path, quiet=True).stdout.strip()
    if not branch or branch == "HEAD" or claude_git(["check-ref-format", "--branch", branch], path, quiet=True).returncode != 0:
        sys.exit("svc: no branch to push (detached HEAD?) – svc git push <name> <branch>")
    if mirror_fetch(name, git) is None:
        return 1
    m = mirror_path(name)
    stage = core.stage_dir(core.CLAUDE_USER)
    try:
        b = os.path.join(stage, "push.bundle")
        if claude_git(["bundle", "create", "--quiet", b, f"refs/heads/{branch}"], path).returncode != 0:
            sys.exit(f"svc: branch {branch} not found in {path}")
        if git_run(["fetch", "--quiet", b, f"+refs/heads/{branch}:refs/tentaclai/push"], cwd=m).returncode != 0:
            return 1
        commit = git_run(["rev-parse", "--short", "refs/tentaclai/push"], cwd=m).stdout.strip()
        action = f"git push {branch} ({commit}){' --force' if force else ''} → {git['url']}"

        def push():
            r = git_run(remote_args(name, git) + ["push", "--quiet"] + (["--force"] if force else [])
                        + ["origin", f"refs/tentaclai/push:refs/heads/{branch}"], cwd=m)
            return r.returncode
        rc = gate.guarded(name, "git", gate.access_mode(git), action, push)
    finally:
        git_run(["update-ref", "-d", "refs/tentaclai/push"], cwd=m, quiet=True)
        shutil.rmtree(stage, ignore_errors=True)
    if rc == 0:
        bundle_to_claude(name, git, path)
        print(f"✓ {name}: pushed {branch} ({commit})")
    return rc


def cmd_git_credential(services, name, op):
    """git credential helper protocol – answers 'get' with the token from .env (only for svc's own git, never for Claude)"""
    sys.stdin.read()
    if core.via_sudo():
        sys.exit("svc: git-credential is internal")
    svc = services.get(name)
    if op != "get" or not svc or not core.enabled(svc) or "git" not in svc:
        return 0
    auth = core.render(svc["git"].get("auth") or {})
    if auth.get("type") == "token" and auth.get("token"):
        print(f"username={auth.get('username') or 'x-access-token'}")
        print(f"password={auth['token']}")
    return 0


def git_push_hook(services, name, args):
    """pre-push hook of every working copy: plain `git push` has no credentials – push through svc instead"""
    sys.stdin.read()
    print(f"tentaclai: push with `svc git push {name} [branch]` – credentials, access mode and approval are handled there.",
          file=sys.stderr)
    return 1
