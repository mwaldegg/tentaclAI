# CLAUDE.md – developing tentaclAI

Guidance for Claude Code (and humans) working **on** this repository. It is not the instruction file of the sandbox –
that one is generated from `build/CLAUDE.base.md` by `build/claude-instructions`.

## What this is

tentaclAI = sandbox + service gateway for Claude Code. Three containers (`compose.yaml`):

- `claude` → container **tentaclai** (`build/`): Claude Code, `svc` (service gateway), `tc-scan`, remote control loop,
  web-app tools (Playwright + headless Chromium in `/opt/pw-browsers`, `tc-shot`; `PLAYWRIGHT_VERSION` pins npm and pip
  package together; their env vars are passed through `entrypoint.sh`'s clean environment).
  `build/svc` is only the entry point; svc's code is the package `build/svclib/` (→ `/usr/local/lib/tentaclai/svclib`,
  layout in its `__init__.py`): `core` (imports no other part), `gate` (lookup with the job limit, audit, approvals,
  `guarded()`), `safeguards` (redaction, untrusted framing, injection scan), one `*_part` module per command family,
  `catalog`, `cli`. Modules use each other only as modules (`core.ENV`, `gate.audit(…)`), never `from .x import name` –
  a value set or patched in one place must be the same everywhere; at import time only `core` may be used. Tests reach
  every name as `svc.<name>` (a proxy to its home module in `tests/test_svc.py`).
  Only in the `internal` network `sandbox` – no route out except through the egress gateway.
- `egress` → container **tentaclai-egress** (`egress/gw.py`): forward proxy (CONNECT any port, plain HTTP, no TLS
  interception). Gets its policy from tentacontrol (`/internal/egress/*`, cached in its volume), records every
  destination. Order: built-in list (`lib/egress-default.txt`, never blockable) → blocklist → own allowlist → tentacles
  (`tclib.reach_hosts`, derived live) → grants → `EGRESS_MODE` permissive/enforce (+ `EGRESS_DIRECT_IP` for IP targets);
  `learn` is resolved by tentacontrol (`egress.mode()`: permissive, then enforce in `.env`) – the gateway only sees the two.
- `control` → container **tentacontrol** (`control/`): web admin, FastAPI + Jinja + HTMX, vendored JS (no CDN at runtime).
  In both networks; network rules in `data/control/egress-rules.json` (`control/app/egress.py`). `main.py` holds the
  app, middleware and background loops; pages and endpoints live in `routes/` (one router per area: `system`,
  `tentacles`, `ssh`, `network`, `settings`, `backup`, `claude`, `jobs`), shared helpers (`page`, `respond`, the *Apply now* hint) in `web.py`,
  small JSON state files go through `jsonstore.py`. Log lines go through `log.get("<area>")` (`log.py`: text or JSON
  per `LOG_FORMAT`, with the request id), never `print` – except the setup link, which scripts grep for. Approvals and
  grants (`activity.py`) are kept in `data/control/approvals.json` – call `save()` after every change of them. Accounts (`data/control/users.json`: username, email, name, bcrypt
  hash, role; Community has one admin, the list leaves room for more) and sessions are `auth.py` – the session holds the
  account's id, `auth.username(request)` names the user in the audit log and on approvals. The audit log: format, files, rotation, search, export and the RFC 5424
  formatter, and the search (`audit_query`, `audit_view` – the field names of page, facets and CSV –, `audit_facets`,
  `audit_histogram`) are `tclib.audit_*` (shared with `svc`); tentacontrol's side (its own entries, Logs → Audit, the ⚠ badge,
  retention) is `auditlog.py` – never write or parse `audit.jsonl` anywhere else. Scheduled jobs: `scheduled.py` (runner, scheduler, step logs –
  not `jobs.py`, which runs tentacontrol's own build jobs); `svc` recognises a job run by the `tc-job=<run>` marker in
  an ancestor's command line plus root's `data/control/job-runs.json`.

**Modules / Community / Enterprise:** tentacontrol loads extensions through `control/app/extensions.py` (Extension API
v1, `docs/extensions.md`): registration via `Api` in `register(api)`, runtime helpers in `control/app/extapi.py` – the
only parts of `app.*` an extension may use; keep both stable (a change that breaks them needs a new `API_VERSION`).
Origins decide the rights: *configured* (`TC_EXTENSIONS`, none by default – may
`provide_license()` and replace pages/templates), *signed* (a module package from Modules → Install from file, signed
with a key in `packages.PACKAGE_KEYS` – same rights as configured, always on; `control/app/packages.py`, format in
`docs/extensions.md` → Packages, tests `tests/test_packages.py`), *builtin* (`control/extensions/` → `/app/extensions/`) and *local*
(`local/extensions/` or an unsigned package, third-party) – both off until enabled (`data/control/extensions.json`), only below `/x/<name>/`,
templates as `<name>/…`; their code is never imported before they are enabled. The example `examples/extensions/tcx_hello`
is also the test fixture (`tests/test_extensions.py`); the built-in `control/extensions/tentaclai_health` (Service-Health,
`tests/test_health.py`) uses the public API only – keep it that way, it is the proof the API is enough. Keep Enterprise code out of this repository – here only the
extension points and the placeholders (Enterprise part of Modules locked, Settings → License).

**Central management (agent):** `control/app/central.py` – this installation as an agent of tentaclAI Enterprise
(protocol `docs/central.md`, sidebar → Enterprise, `routes/central.py`, tests `tests/test_central.py` with a fake server).
Profiles are applied through `backup.preview/apply` (item ids = import preview ids, `hash_old/hash_new` per row);
enforced items are refused by `_central_check()` in the stores (and `update_env` for settings) unless
`central.applying()`, and by `tclib.central_locked()` in `svc config put`. Keep new writers of managed parts behind the
same check. Sign-in through the server: `central.sso_start/sso_finish` (signed assertion, nonce in the session), routes
`/sso/*` in `routes/system.py`; a server user's session carries the user (`c:<sub>`, no local account –
`auth.is_central`), `central.local_sign_in()` applies the *Enterprise only* policy and the emergency access
(`breakglass.json`, `passwd.py --open`).

Two layers: `svc` decides *what* happens with a tentacle (credentials, `read`/`write`/`confirm`); the gateway decides *where*
the sandbox may connect. ssh/rsync go through `ProxyCommand tc-connect`, databases and mail through `svc`'s local `tunnel()`.

Shared logic lives in **`lib/tclib.py`** (`.env`, `${VAR}`, services, systems, SSH hosts) and is copied into both images –
`svc`, `tc-scan`, `claude-instructions` and tentacontrol use it. Never re-implement these parsers elsewhere; extend tclib.
All images build from the repository root (`.dockerignore` whitelists `build/`, `control/`, `lib/`, `egress/`, `VERSION`).

Display name **tentaclAI**, technical name **tentaclai** (container, image, paths, scripts). See `README.md` for the
architecture and `CONTRIBUTING.md` for the ground rules.

## Rules

- **Generic code only.** Site data lives in git-ignored files (`.env`, `services/*.json`, `systems/*.json`, `ssh/`,
  `local/CLAUDE.md`, `compose.override.yaml`, `data/`). Before every commit check `git diff --cached --name-only` –
  never commit them, nor tokens, hostnames or IPs of a real installation.
- **English** for code, UI, messages, docs, templates and commit messages.
- **Guard rails stay intact:** `svc` enforces `read`/`write`/`confirm`, secrets never go into argv, logs, the UI or Claude's context.
  Every write goes through `guarded()` in svc (`svclib/gate.py`): it logs *started* (`audit(…, strict=True)` – fail closed) before the
  write and the result with `intent=<that id>`; readers use `tclib.audit_read`/`audit_lines(settled=True)`, which hide
  a settled *started* entry. Every entry of one svc call carries its `cid` (`CID` in svc, also sent with the approval
  request); tentacontrol's entries get the request id (`auditlog.write`). Where a write can't end svc (the MCP proxy
  answers a refused tool call and goes on) use `gate.admit()` / `gate.finish()` – the two halves of `guarded()`;
  MCP servers are always registered as `svc mcp-proxy` (`mcp_part.ToolGate`), never directly. Risk hints for approvals are `tclib.write_risks` – a grant never covers a risky write.
- **Privilege separation:** Claude runs as user `claude`, `svc`/`tc-scan` as root via sudo, client tools as `tcrun`
  (`runner()` in svc). Code running as root must never read, write or run git in paths Claude controls (workspace, its
  home) – hand files over as the other user (`as_user`, `write_as_claude`, staging dirs) and never pass Claude's
  arguments to a root process that touches local files. New secrets go to the client tool via 0600 files/env of `tcrun`.
- **Test in stages**, never on a running installation:
  1. **After every change:** `scripts/test-quick.sh` (seconds, no Docker) – syntax, ShellCheck, site data, JSON/YAML,
     pytest unit tests in `tests/` (tclib, parsers, connector/skill state) and every tentacontrol page rendered with
     dummy data. New logic gets a unit test there; new pages go into `tests/test_pages.py`.
  2. **Only for changes to security boundaries, the gateway or the entrypoint** (svc access modes, privilege
     separation, `egress/`, `build/entrypoint.sh`, managed settings): `REUSE=1 ONLY=<sections> scripts/test-sandbox.sh`
     – sections `priv svc egress notify skills pages`; `REUSE=1` keeps the stack in `/tmp/tctest-reuse` and rebuilds
     only images whose sources changed.
  3. **Only before a tag:** the full `scripts/test-sandbox.sh` (see Releases).
  `test-sandbox.sh` works in a scratch copy with its own compose project `tctest`, guarded with `set -e` + a cwd check.
  Never write `.env`/compose files or run `docker compose` before checking that the current directory is the scratch
  copy – a failed copy step once ran test commands in the live stack. Waits poll for a condition, never fixed `sleep`s.
  The script runs as root locally but **not in CI**: read root-only files (`data/control/*`, `.env`) through a container
  (`docker exec tctest-claude cat …`), never directly from the host. A check that expects a refusal must test the
  refusal itself (e.g. the gateway's `403` via `%{http_connect}`), not just `000` – a timeout also gives `000`.
  Checks slower than 2 s print their time – look there first when a run gets slow.
  Recreating the real `tentaclai` container ends running sessions and Remote Control – only after asking.
- **Templates:** every page must render in `tests/test_pages.py` (a stray `'` in a Jinja string is a 500) – add new pages there. Keep user-facing
  wording plain (e.g. *Rule*, *No rule*, *Built-in*, *IP targets*) and explain modes in README → Network control and Help.
- Keep README, tentacontrol → Help (`control/app/templates/help.html`) and this file in sync with behaviour changes.

## Releases

Versioning: semantic versions, git tag `vX.Y.Z` on `main`, published as a GitHub release.

Every release gets an entry in **`CHANGELOG.md`** (newest first) and the same text as GitHub release notes, with:

1. **Highlights** – what is new, in a few bullets.
2. **Changes / fixes** – noteworthy changes, especially anything that behaves differently.
3. **Upgrade** – *mandatory*: exact steps to update an existing installation from the previous release, e.g.
   - `git pull` in the stack directory
   - which images to rebuild (`docker compose build`, or `build claude` / `build control`)
   - which containers to recreate – and that recreating `tentaclai` ends sessions and Remote Control
   - new or changed `.env` variables (name, default, whether required)
   - renamed or moved files and paths, config format changes, data migrations (with commands)
   - breaking changes and how to roll back
   If nothing special is needed, say so explicitly (e.g. “`git pull`, `docker compose build`, `docker compose up -d`”).
4. **Known issues** – if any.

Release with **`scripts/release.sh X.Y.Z "subtitle"`** (`--dry-run` first if unsure): it refuses unless main is clean
and up to date and `## Unreleased` has an `### Upgrade` part, runs the **mandatory** tests – `scripts/test-quick.sh` and
the **full** `scripts/test-sandbox.sh` (fresh images and state, a kept REUSE stack is removed), pushes main and waits for
the GitHub `checks` workflow of that commit to be green – and only then renames the section, sets `VERSION`, commits,
tags, pushes and creates the GitHub release from the same notes. Test the upgrade path from the previous release in an isolated instance when the Upgrade section is more than a
plain rebuild.

## Brand images

`docs/brand/*.png` (GitHub social preview, wordmarks) are generated: edit slogan, subtitle and styles in
`docs/brand/src/gen.py`, then run `scripts/build-brand.sh` (Docker + Playwright). The slogan also appears in
`README.md` and the brand block of `control/app/templates/base.html` / `login.html` – keep them in sync.
`docs/screenshots/*.png` come from `scripts/build-screenshots.sh` (made-up demo site, local tentacontrol image) – run it
before `build-brand.sh` when the UI changed, the social preview uses the topology screenshot.
