#!/usr/bin/env bash
# Release tentaclAI: checks, stage 1 + full stage 3 tests, CHANGELOG/VERSION, commit, tag, push, GitHub release.
#   scripts/release.sh 0.9.1 "subtitle"        release v0.9.1 named "v0.9.1 – subtitle"
#   scripts/release.sh --dry-run 0.9.1 "…"     checks and tests only, changes nothing
# Needs: the "## Unreleased" section in CHANGELOG.md (with an "### Upgrade" part), a clean working tree on main that is
# not behind origin, and a GitHub token with contents:write – GH_TOKEN from the environment or the stack's .env (never
# printed, handed to git through a credential helper). Extra commit trailers: RELEASE_TRAILERS="Co-Authored-By: …".
# Before the release commit, main is pushed (if needed) and the GitHub "checks" workflow of that commit must be green –
# a red CI stops the release before anything is tagged.
set -euo pipefail
cd "$(dirname "$0")/.."
die() { echo "✗ $*" >&2; exit 1; }
step() { echo "== $*"; }
DRY=""; ARGS=()
for a in "$@"; do  # --dry-run anywhere – after the subtitle it once went unnoticed and released for real
    case "$a" in
        --dry-run) DRY=1 ;;
        -*) die "unknown option $a" ;;
        *) ARGS+=("$a") ;;
    esac
done
[ "${#ARGS[@]}" -le 2 ] || die "too many arguments – quote the subtitle"
VER="${ARGS[0]:-}"; TITLE="${ARGS[1]:-}"
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "usage: $0 [--dry-run] X.Y.Z [\"subtitle\"]"
REPO="$(git remote get-url origin | sed -E 's#^(https://github.com/|git@github.com:)##; s#\.git$##')"

step "checks"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on main"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "uncommitted changes – commit them first"
git rev-parse -q --verify "refs/tags/v$VER" >/dev/null && die "tag v$VER exists already"
CUR="$(cat VERSION)"
[ "$(printf '%s\n%s\n' "$CUR" "$VER" | sort -V | tail -1)" = "$VER" ] && [ "$CUR" != "$VER" ] || die "$VER is not newer than $CUR"
grep -q '^## Unreleased$' CHANGELOG.md || die "CHANGELOG.md has no '## Unreleased' section"
NOTES="$(awk '/^## Unreleased$/{f=1;next} /^## v[0-9]/{f=0} f' CHANGELOG.md)"
[ -n "$(echo "$NOTES" | tr -d '[:space:]')" ] || die "the Unreleased section is empty"
echo "$NOTES" | grep -q '^### Upgrade' || die "the Unreleased section has no '### Upgrade' part (mandatory)"
if [ -z "${GH_TOKEN:-}" ]; then
    GH_TOKEN="$(python3 -c 'import sys; sys.path.insert(0, "lib"); import tclib; print(tclib.read_env(".env").get("GH_TOKEN", ""))')"
fi
[ -n "$GH_TOKEN" ] || die "no GH_TOKEN (environment or .env)"
export GH_TOKEN
git_auth() { GIT_TERMINAL_PROMPT=0 git -c credential.helper= \
    -c credential.helper='!f() { echo username=x-access-token; echo "password=$GH_TOKEN"; }; f' "$@"; }
git_auth fetch -q origin main
[ "$(git rev-list --count HEAD..origin/main)" = 0 ] || die "main is behind origin/main – pull first"
echo "   v$CUR → v$VER, $(git rev-list --count "v$CUR"..HEAD 2>/dev/null || echo '?') commits since v$CUR"

step "stage 1: quick checks"
scripts/test-quick.sh >/dev/null || die "scripts/test-quick.sh failed – run it for details"
step "stage 3: full sandbox test (fresh images and state)"
REUSE=1 CLEAN=1 scripts/test-sandbox.sh >/dev/null 2>&1 || true   # a kept REUSE stack would block the full run
LOG="$(mktemp)"
scripts/test-sandbox.sh >"$LOG" 2>&1 || { tail -30 "$LOG"; die "full sandbox test failed (log: $LOG)"; }
grep -o 'passed: [0-9]*  failed: [0-9]*' "$LOG"; rm -f "$LOG"

step "GitHub CI of $(git rev-parse --short HEAD)"
SHA="$(git rev-parse HEAD)"
if [ "$(git rev-list --count origin/main..HEAD)" != 0 ]; then
    if [ -n "$DRY" ]; then echo "   (dry run: main is ahead of origin – a real run pushes it and waits for CI)"; SHA=""; else git_auth push -q origin main; fi
fi
api() { curl -s -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$1"; }
if [ -n "$SHA" ]; then
    end=$((SECONDS + 1200)); state=""
    while [ $SECONDS -lt $end ]; do
        state="$(api "actions/workflows/checks.yml/runs?head_sha=$SHA&per_page=1" | python3 -c 'import json, sys
r = (json.load(sys.stdin).get("workflow_runs") or [{}])[0]
print(r.get("status", "missing"), r.get("conclusion") or "-", r.get("html_url", ""))')"
        case "$state" in completed\ *) break ;; esac
        sleep 15
    done
    case "$state" in
        "completed success "*) echo "   green: ${state##* }" ;;
        completed\ *) die "CI failed: ${state##* } – fix it, nothing was released" ;;
        *) die "CI did not finish within 20 minutes ($state) – nothing was released" ;;
    esac
fi

NAME="v$VER${TITLE:+ – $TITLE}"
if [ -n "$DRY" ]; then
    echo "✓ dry run – would release \"$NAME\" to $REPO with these notes:"; echo "$NOTES"; exit 0
fi

step "commit, tag, push"
sed -i "0,/^## Unreleased\$/s//## v$VER – $(date +%F)/" CHANGELOG.md
echo "$VER" > VERSION
git add CHANGELOG.md VERSION
git commit -q -F - <<EOF
Release v$VER
${RELEASE_TRAILERS:+
$RELEASE_TRAILERS}
EOF
git tag -a "v$VER" -m "v$VER"
git_auth push -q origin main "v$VER"

step "GitHub release"
BODY="$(mktemp)"
python3 - "$VER" "$NAME" "$NOTES" >"$BODY" <<'PY'
import json, sys
print(json.dumps({"tag_name": "v" + sys.argv[1], "name": sys.argv[2], "body": sys.argv[3].strip()}))
PY
URL="$(curl -s -X POST -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/releases" --data @"$BODY" | python3 -c 'import json, sys; print(json.load(sys.stdin).get("html_url", ""))')"
rm -f "$BODY"
[ -n "$URL" ] || die "tag v$VER is pushed, but creating the GitHub release failed – create it by hand"
echo "✓ $NAME released: $URL"
