# Changelog

All notable changes, newest first. Every release lists **upgrade steps** from the previous one.

## Unreleased

### Highlights
- **Job groups:** sort jobs by topic – an optional *Group* per job (editor: click an existing group or type a new
  one; on each card a menu to move it, *New group…* included), one tab per group on the Jobs page with the number of
  jobs and a warn/alert count, the page remembers the tab you picked. `svc jobs --group <group>` lists one group;
  `svc config put job` takes `group` (left out, the job keeps its group).

- **Network approvals name the process:** while the gateway holds a connection to an unknown destination, tentacontrol
  asks the sandbox (`svc origin-of`, root) which process holds it – the card shows its command and user, the Claude
  session (or job) and terminal it belongs to, and how many connections wait for the same decision. The audit entry of
  the decision keeps them, plus when it was first requested (`requested` – the entry's time is your decision).

- **PDFs are checked, images no longer flagged:** a JPEG or PNG Claude reads (or an MCP tool returns) is no longer
  flagged as a *long base64 block* – that was the file itself. A PDF's text is taken out with `pdftotext` (first 50
  pages, 5 s) and checked page by page for injection attempts, hidden white text included; a finding names the page.
  A PDF that can't be read gets *PDF text not checked* on its audit entry. Base64 inside text (a mail, a page, `cat`)
  is still a finding.

### Changes / fixes
- Git services: `"author": {"name": …, "email": …}` in the `git` part sets the commit author of that working copy
  (applied by `svc git sync` / `svc sync`); without it the installation's default is used (Settings → Git name /
  email, `GIT_USER_NAME` / `GIT_USER_EMAIL`). The service page shows which one applies.
- Jobs: a suggested better task is now a minimal change – no line or issue numbers, findings or workarounds of the
  run, lasting facts go to notes – and shows as a diff against the task the run had, with the word count
  before → after; a suggestion equal to the task is dropped (#26).
- Services: a template's setup hint is shown once when the service is created instead of being saved as a note
  Claude reads after every onboarding; the PatchMon template keeps its token hint in `_meta.setup` now (#20).
  Existing services keep their notes – remove a copied setup hint by hand if one is there.
- Fix: when the injection guard flagged a JSON response (e.g. GitHub issues with repro commands), svc appended its
  warning to stdout too, so `svc … | jq` failed with a parse error. For JSON the warning now goes to stderr only.
- Fix: behind a reverse proxy that keeps connections open (nginx-proxy does), a request now and then failed with
  *the server closed the connection* – uvicorn dropped idle connections after 5 s while the proxy reused them for up to
  60 s. tentacontrol now keeps them 75 s.
- Logs → Audit: each row shows its source (session, terminal, job, host) under the actor – a click filters by it.
- Logs → Audit CSV export: new columns at the end – `cid`, `process`, `requested`, `attempts`.
- Fix: `svc help`, `svc --help` and plain `svc` printed one line instead of the usage with all commands.
- Jobs with *Propose actions*: the prompt and the schema now name every rule a proposed command must follow (500
  characters, one line, no backslash or backtick, the refused svc commands), and a refused proposal names its reason
  (e.g. *invalid: longer than 500 characters*, *invalid: contains ;*). A too long command is checked as a whole, not cut first.
- Fix: Logs → Audit: *filter* / *exclude* on a network entry's `process`, `requested` or `attempts` found nothing and
  named the field unknown – they are search keys now.
- tc-guard: a `base64`/`data`/`blob` value in a tool result is skipped as a file only in Read's file result or next to
  an image/audio/video/PDF media type, and only when it looks like base64 – other text under these keys is scanned for
  prompt injection again.
- Sandbox rules and `svc help`: `svc files` reads files only of a service with a files part – on a plain SSH or Docker
  host the rules now point to `svc ssh <host> cat <path>` instead.
- tc-guard: all PDFs of a tool result share one 6 s budget for `pdftotext` (before: 5 s each, so several slow PDFs
  could exceed the 10 s hook timeout and lose the audit entry); an unreadable PDF keeps *PDF text not checked* even
  when a later one reads fine, and a scan cut at 50 pages or 200k characters notes *PDF text partly checked* (#38).
- Injection guard: output with deeply nested JSON no longer stops svc's guard before its warning, audit entry and
  notification (#42).
- Jobs: a proposed command with leading spaces is stored as it was checked, no longer cut at the end (#43).
- Jobs: the proposal prompt also names balanced quotes, svc ssh with a command and no svc db shell – rules a proposal
  was refused for without knowing them (#44).
- Services: the setup hint of a second service from the same template (e.g. PatchMon) names that service's own
  variables instead of the first one's (#54).

### Upgrade
- `git pull`, `docker compose build`, `docker compose up -d` – all three images change (gateway, svc, tentacontrol):
  recreating `tentaclai` ends running sessions and Remote Control. The sandbox image now contains `poppler-utils`
  (`pdftotext`). Nothing else to do.

## v0.23.0 – 2026-10-26

### Highlights
- **Writes are logged before they run (fail closed):** `svc` writes a *started* entry before every write of a `write` or
  `confirm` tentacle and only runs it when that worked; the result follows with a link to it. A write that can't be
  logged (full disk, broken permissions) is refused with a clear message and a notification (*Audit log not writable*,
  priority high). Logs → Audit shows one entry per write – a *started* entry is only left when the call never finished
  (interrupted, timed out, still running).
- **Risky writes stand out:** Approvals and the approval banner mark actions like a privileged container, a mounted
  `/` or Docker socket, host namespaces, `docker rm`/`prune`, `compose down (-v)`, `exec`, `rm -rf`, disk tools,
  reboots, firewall or account changes, `curl … | sh`, `DROP`/`TRUNCATE`, `DELETE`/`UPDATE` without `WHERE` and force
  pushes in red with the reason, and say what approving gives (Docker on a host = root there; a shell's user).
  **Approve + 15 min no longer covers risky writes** – they are asked for one by one.
- **Network learning phase for new installations:** `.env.example` now sets `EGRESS_MODE=learn` – permissive for
  `EGRESS_LEARN_MINUTES` (60) from the sandbox's first connection, then `enforce`; the Network page offers the
  destinations seen meanwhile without a rule (*Allow all*, or one by one), plus a notification (*Network learning over*).
- **MCP tool calls are gated:** every MCP server now runs behind `svc mcp-proxy` (also those without tokens, and stdio
  servers as a child process run by `tcrun`), and its `mcp` part gets an `access` like every other part. Tools the
  server marks read-only (`readOnlyHint`) run freely; every other tool call is a write – `read` hides and blocks it,
  `write` logs it (fail closed), `confirm` asks in Approvals first, with tool and arguments on the card; a tool marked
  `destructiveHint` is a risky write (never covered by a grant). `"read_tools"` / `"write_tools"` in the `mcp` part
  correct the server's marks. The service page lists the tools with their kind. Jobs: a read-only job now gets the MCP
  servers of the services with only their reading tools, a job limited to its tentacles the MCP servers of the named
  ones (before: no MCP server at all; claude.ai connectors stay off in both).
- **Faster first setup:** `./tentaclai.sh init` asks one question (how to reach tentacontrol – default now the LAN
  on port 8484) and builds and starts everything; the rest has defaults (Settings, or `init --advanced` for every
  question). **Add host** has *This host* and a *Docker host* box (on by default): after the login it checks Docker,
  finds the stacks directory from `docker compose ls` and adds the Docker service with access *confirm*.

### Changes / fixes
- Settings → Account: a user signed in through tentaclAI Enterprise gets a page of their own (no password or
  two-factor forms); whether a local profile still needs username and email is asked about the signed-in user.
- The Jobs badge and the Jobs page's refresh read the run history only when it changed.
- Logs → Audit: the outcome is the stored decision (allowed, read, auto …) instead of a plain *ok* – searches for
  `outcome:ok` now only match entries stored as ok (use `-outcome:failed` or the green values); the colours are unchanged.
- Approvals and *Approve + 15 min* grants survive a restart of tentacontrol (`data/control/approvals.json`, 0600): a
  pending request stays pending, a decision is still used only once, and `svc` keeps waiting while tentacontrol is
  away (up to 2 minutes) instead of failing.
- Correlation id: every audit entry of one `svc` call carries the same `cid` (search `cid:<id>`; on the approval card
  as *call …*), tentacontrol's entries the id of their web request (also the `X-Request-ID` response header).
- tentacontrol logs through one logger: `LOG_FORMAT=text` (default) or `json` for a log shipper, `LOG_LEVEL`; each
  line of a web request names its request id.
- `svc` is split into a package (`build/svclib/`, installed to `/usr/local/lib/tentaclai/svclib`): `core`, `gate`
  (access, audit, approvals), `safeguards`, one module per service part, `catalog`, `cli` – `build/svc` is only the entry
  point. No change in behaviour.
- Audit: a tool call of a service's MCP server is logged once, by svc's proxy (part `mcp`, with exit code and time) –
  the `PostToolUse` hook no longer adds a second *tool* entry for it (claude.ai connectors are logged as before).
- MCP `insecure_tls` now applies to every http MCP server (svc makes the connection); the transport `sse` can't be
  proxied – use `http` (Streamable HTTP).
- Renaming a service or SSH host also updates the job tasks that name it (`@name`, `svc … name`); deleting one a
  job names warns, and Jobs marks a job whose task names a tentacle that no longer exists – before, the job only
  failed when it ran.
- Jobs limited to their tentacles: a tentacle the task calls with `svc` (`svc mail box list`) counts as named, like
  `@box` – before, only `@name` did and such a call was refused at run time; the editor shows what the job may use.
- Jobs: the runs the sidebar badge counted are listed on top of the page (*New since your last visit*, with a link to
  each run – also older runs, whose history opens with them marked *new*; *Mark all seen* clears it); before, only each job's latest run was in
  sight.
- Fix: `svc list` (and `svc systems <name>`) ran a long service name into its type column – the columns now fit
  the longest entry.
- Enterprise page: the managed parts show short names – the details (e.g. *local/CLAUDE.md*) are tooltips.
- Fix: the quota notification came again and again once a limit was passed – it was keyed by the reset time, which
  Claude Code prints to the minute, and forgotten on every restart. It now goes out once at 80 % and once at 100 % per
  limit window (state in `data/control/usage-warned.json`).

### Upgrade
- `git pull`, `docker compose build`, `docker compose up -d` – the fail-closed audit is in `svc`, so the sandbox image
  changes too: recreating `tentaclai` ends running sessions and Remote Control.
- Existing installations keep their network mode (`EGRESS_MODE` in `.env` stays as it is). To get the learning phase,
  set `EGRESS_MODE=learn` (optional `EGRESS_LEARN_MINUTES=60`) and `docker compose up -d control` – or switch to
  *enforce* on the Network page once *Seen* has what you need.
- The audit log gains *started* entries and an `intent` field on results; older entries are read as before. A SIEM or
  script reading `audit.jsonl` directly sees both lines – skip `"decision": "started"` entries whose id a later
  entry names in `intent`. New entries also carry a `cid` field.
- Optional new `.env` variables `LOG_FORMAT` (`text`, default) and `LOG_LEVEL` (`info`) – `compose.yaml` passes them to
  tentacontrol; log lines now start with a timestamp and level (`… WARNING usage: …`). A script grepping
  `docker logs tentacontrol` for the setup link keeps working.
- Approvals pending while you upgrade survive the recreation of tentacontrol only from this version on.
- **MCP access:** on its first start tentacontrol sets `"access": "write"` in every existing `mcp` part without one
  (backup `services/<name>.json.bak-<date>-mcp`, once – marker `data/control/migrated-mcp-access`): the tools keep
  working as before, now logged. Consider `confirm` for servers that change things (Home Assistant, n8n – the templates
  now use `confirm`), or `read`. New `mcp` parts without `access` read. A service file restored from an older backup
  later reads too.
- Claude's MCP configuration is rewritten by `svc sync` at the start of the `tentaclai` container (every server becomes
  `svc mcp-proxy <name>`); running sessions see it after `/mcp` → reconnect. stdio servers without secrets now run as
  `tcrun` instead of `claude` (own home `/var/lib/tcrun`) – a server that relied on Claude's home or files needs them
  passed in `env`/`args`. An MCP part of type `sse` stops working – switch it to `http`.
- `svc` now lives in `build/svclib/` as well – rebuild the `claude` image (`docker compose build claude`); a fork that
  copies `build/svc` alone into its own image must copy `build/svclib/` to `/usr/local/lib/tentaclai/svclib/` too.

## v0.22.0 – 2026-10-25

### Highlights
- **Modules for everyone – Extension API v1**: tentacontrol loads modules that bring pages, sidebar entries (with a
  badge), tabs in Settings/Logs/Claude, icons, static files, background tasks, notification events, an audit log hook,
  Help sections and parts of Export / Import. **Modules** is no longer locked in Community: it lists *built-in* modules
  (shipped, off until enabled), *third-party* ones (`local/extensions/<name>/`, off until enabled, with a warning – they
  run with tentacontrol's rights) and signed packages. Enabling takes effect after *Restart tentacontrol* (a few
  seconds, the sandbox keeps running), disabling at once. Third-party modules live below `/x/<name>/` and can't replace
  tentacontrol's pages. `TC_EXTENSIONS` names packages loaded always (none by default). Guide: `docs/extensions.md`,
  example `examples/extensions/tcx_hello`.
- **Service-Health** – the first built-in module (Modules → enable): `svc test` of every service on a schedule
  (1–60 minutes, default 5), a Health page with the state, a 24-hour bar and the availability over 24 hours and 7 days
  per service and system, a sidebar badge counting services that are down, and the notifications *Service down*
  (urgent) / *Service up again* after a set number of failed checks in a row (default 2). Settings → Health picks the
  interval and the services; the history (7 days) stays in `data/control/ext/tentaclai_health/`.
- **Install modules from a file** (Modules → *Install from file*): a module package (`.tcpkg.zip`) is checked – size,
  paths, file types, SHA-256 of every file – and shows name, version and signature before anything is installed. A
  package signed by tentaclAI gets the rights of a module named in `TC_EXTENSIONS`; an unsigned one is a third-party
  module after *I trust this code*. Every file is checked again at each start, an update keeps the previous version
  for *Roll back*, *Remove* deletes it. Format: `docs/extensions.md` → Packages.
- **tentaclAI Enterprise – central management** (sidebar → **Enterprise**): tentaclAI Enterprise is a server of its
  own; the license lives there (seats = installations), tentacontrol needs none. While the installation runs on its
  own, the Enterprise page has a lock, says what Enterprise adds and takes the enrollment code. Once enrolled, the
  installation is an agent: it always connects to the server, sends its status (version, modules, services – no
  credentials) and its audit log (nothing unsent is pruned), and applies the server's signed profile – enforced items
  are locked (marked *central*, refused in tentacontrol and in `svc config put`, reverted when changed on the host),
  defaults may be changed locally, built-in modules and signed packages can be set. The local admin picks which parts
  the server may manage and can change that later; credentials stay in `.env`. A dot in the sidebar shows the
  connection (connected / connection failed / revoked); the page shows the server, last contact, the profile and when
  it arrived, the audit backlog and the central jobs. Protocol: `docs/central.md`.
- **From tentaclAI Enterprise:** a profile can hide parts of tentacontrol (Terminal, Jobs, Network, Modules, Claude,
  Export / Import, Updates – part *Features*), and the server can show a banner on every page (× closes it until the
  next sign-in).
- **Tamper protection from tentaclAI Enterprise:** a profile can protect the management – no *Leave* button, *Managed
  by Enterprise* can only grow (or is locked completely, or set to all parts); attempts are refused, logged and shown on the central.
- **Sign-in through tentaclAI Enterprise** (part *Sign-in*, needs `CONTROL_URL`): users of the central sign in with
  *Sign in with <server>* on the sign-in page – no local account, the central checks password, second factor and its
  grants and sends back a signed assertion valid for 60 seconds. A profile can allow only these sign-ins
  (*Enterprise only*); the local admin then gets in only with the emergency access from the host:
  `./tentaclai.sh passwd` or `./tentaclai.sh passwd --open` opens the local sign-in for an hour.

### Changes / fixes
- `svc <name> GET …`: an HTTP error (4xx/5xx) now exits non-zero (curl 22, the body is still printed) – calls that read
  the status themselves with `-w` (svc test, Test API, tc-scan) or pass `--fail` behave as before. A path that repeats
  the base URL's prefix (`/api` + `/api/states`) gets a hint (#18).
- `svc audit` and Logs → Audit: a `field:value` with a field that doesn't exist (`status:denied`) is still searched as
  text, but now with a hint naming the real fields (#17).
- `svc audit … | head` and other svc output into a closed pipe end quietly instead of with a traceback (#16).
- Product findings → GitHub: the issue title no longer ends at "e.g." / "i.e." / "etc." / "vs.".
- Modules: the header says *Enterprise · licensed* or *Enterprise · no license* (it showed a green *Enterprise* as
  soon as the package was loaded), and the license provider's card gets a *licensed* / *no license* pill.
- Extension API: `extapi.services()` and `extapi.systems()` list the connected services and systems (no secrets).
- Extensions: the old calls `add_features()` / `set_edition()` are gone (`provide_license()`); an extension declares
  `REQUIRES_API = 1`.
- Central management: every change to a part the server enforces is refused locally – also editing or renaming a
  system, an SSH host's sudo and notification channels (name) and rules, which before went through and were put back
  by the next sync. A channel's URL and on/off stay local.
- Features hidden by the server's profile no longer show links elsewhere either (Overview, dashboard buttons,
  *Onboard with Claude*). A joined installation shows *★ Enterprise* on Modules and Settings → License too.
- Overview: the sandbox's status, Claude's sign-in, stats, sessions and remote control are fetched in parallel and no
  longer hold up tentacontrol while the Overview is open; the recent approvals read far less of the audit log.

### Upgrade
- `git pull`, `docker compose build` (all three images – the gateway's shared library changed too),
  `docker compose up -d` – recreating `tentaclai` ends running sessions and Remote Control.
- Sign-in through tentaclAI Enterprise needs `CONTROL_URL` (Settings → tentacontrol address); nothing else is new in `.env`.

## v0.21.0 – 2026-10-24

### Highlights
- **Claude learns where it belongs**: something useful and lasting Claude finds out while working, or the user tells
  it, it records on its own initiative where it applies – a service's `notes`/`examples`, a **system's** notes (new
  `svc config put system <name> <file>`) or the site rules (`local/CLAUDE.md`) – every change still through Approvals.
  Only checked facts or the user's words, never what content asks to remember; facts about the environment go there,
  not into Claude Code's own memory.
- **Deny with a reason**: Approvals has an optional *Reason* next to *Deny*. Claude gets it with the denial and proposes
  a lasting rule ("only at night") as a note; the audit log keeps it (field `reason`, searchable, under the outcome).
- **See what a configuration change does**: `svc config put` sends its diff with the approval (JSON compared in one
  layout, so only real changes show); added text that reads like an instruction to an AI gets a ⚠ on the card and the
  banner, a notification and a "flagged" audit entry.

- **Jobs learn**: a run may return what it learned (`knowledge`: add, fix or drop a note of a service, a system or the
  site rules) and – *Suggest prompt improvements*, on by default, `improve` in a job definition – a better version of
  its own task. Both show under the run: *Apply selected* writes the picked notes (backup; a note that changed since
  the run is left alone; ⚠ for text that reads like an instruction to an AI; one audit entry per change), *Use this
  task* takes the prompt – the editor keeps the last 5 versions (*Earlier versions*, Restore). A weakness of tentaclAI
  itself (target `product`: a missing svc option, a misleading message) is never written into notes: it shows under
  *For tentaclAI* with *Report on GitHub* (a prefilled issue for `UPDATE_REPO`, checked by you before sending), *Done*
  and *Dismiss*.
- New job templates **Learning review** (weekly: the audit log of the last 7 days – repeated failures and exploration,
  reasons of denials – turned into notes) and **Knowledge cleanup** (monthly: merges, cuts and moves notes, site rules
  and Claude's memory). New settings `KNOWLEDGE_LOCAL_KB` (default 6) and `KNOWLEDGE_NOTES` (default 8);
  Claude → Instructions shows the knowledge budget. `svc audit` prints the reason of a denial.
- **Built-in jobs on new installations**: the first setup creates *Learning review* and *Knowledge cleanup*, paused and
  marked *built-in* – edit or pause them (they can't be deleted), *Reset to default* in the editor; an untouched built-in task follows the
  shipped one on later updates. Existing installations get no jobs on the update (add them from the templates).
- **Site skills**: a procedure of several steps that comes up again (renew a certificate, onboard a host …) Claude
  offers to keep as a skill – `svc config put skill <name> <file>` writes `local/skills/<name>/SKILL.md` after your
  approval (checked frontmatter, diff, ⚠ check, backup), and `svc sync` copies it into Claude's `~/.claude/skills/`, so
  every session and job can use it. Settings → Skills lists them as *site skill* with their steps, mode and *Remove*
  (kept as `.bak-…`). *Learning review* names candidates, *Knowledge cleanup* reports outdated or overlapping ones.
  Settings → Export / Import carries them too (part *Site skills*; on import only picked on request, with a diff and ⚠
  for text that reads like an injection).

### Fixes
- `svc ssh` with several arguments keeps a locally quoted word with spaces or `| & ; < > ( )` as one word on the remote
  side (`svc ssh host docker ps --format '{{.Names}} {{.Status}}'`, `grep -E 'a|b'` broke there); a single argument
  stays the remote command line. When such a one-string command fails and holds an unquoted `|` or `{{…}}`, svc says
  how to quote it. (#15)
- `svc mail <name> <command> --help` prints the options instead of "unknown option --help". (#14)
- Findings for tentaclAI (*Report on GitHub*) are asked for in English and without host, service or user names – the
  tracker is public; the issue title is the first sentence, cut at a word. A finding carries *steps / command*, *actual*
  and *expected*, and the issue an *Environment* block: tentaclAI version and edition, Claude Code version and model
  of the run (recorded from the run's start), the part, date and profile.
- `svc config put service` wrote the file readable by root only, so Claude couldn't read it back; it is `0644` now (no
  secrets in service files). New `svc info <name> --json` prints the service file as stored – the starting point for
  a change (the rule pointed to `svc info`, which prints text). The SSH section of Claude's instructions says how to
  quote a remote command (patterns with `|`, spaces or `{{…}}`) – runs failed on that again and again.
- Renaming a service now also updates `svc mail <name>` in its examples and notes; the PatchMon template named itself
  `patchmon` instead of the placeholder, so a copy under another name had a wrong example (a test checks all
  templates now). Existing services: check examples that still call an old name.

### Upgrade
- `git pull`, `docker compose build`, `docker compose up -d` – both images change (`svc` and the instructions in
  `tentaclai`, Approvals, Jobs, Skills and Export / Import in `tentacontrol`); recreating `tentaclai` ends running
  sessions and Remote Control.
- Nothing to migrate: `reason` (audit), `knowledge`/`improve`/`env` (jobs and runs) are new optional fields; new
  optional `.env` settings `KNOWLEDGE_LOCAL_KB` (default 6) and `KNOWLEDGE_NOTES` (default 8).
- The built-in jobs *Learning review* and *Knowledge cleanup* are created only by the first setup – on an existing
  installation add them from the job templates if you want them. Site skills start empty (`local/skills/`, git-ignored
  with the rest of `local/`).

## v0.20.0 – 2026-10-23

### Highlights
- **One audit log for everything** – tentacontrol → *Logs → Audit*: Claude's tool calls (through the Claude Code hook),
  every `svc` command including reads, network connections of the sandbox (counted per destination and 15 minutes,
  refused ones at once), scheduled job runs, your changes in tentacontrol, terminal sessions, sign-ins and failed
  attempts, tentacontrol's start. Read it like other log tools: a search line with `field:value` terms
  (`actor:claude outcome:denied docker`, `-type:network`, `target:mail*`), a time range picker, filters as chips,
  a sidebar with the values of each field and their counts, a histogram of the events by outcome (click or drag to
  zoom), one value per column (time · actor · type · target · action · outcome), every field of an entry on a click,
  *Load more*, and **CSV / JSONL export** of exactly what matches.
- **Accounts with a username**: the first setup asks for username, email and an optional name; you sign in with
  username + password, and the username names you in the audit log (field `user`, also for failed sign-ins: the name
  that was typed) and on approvals. Settings → *Account* (was *Security*) changes username, email, name and the password.
- **Logs → Containers**: the live log of all three containers (`tentaclai`, `tentaclai-egress`, `tentacontrol`) with a
  line filter and download.

### Changes
- *Activity* is now **Approvals** (`/approvals`; `/activity` links still lead there): pending approvals, active grants
  and **Recent requests** – the latest decided requests of the last 30 days from the audit log (target, action, source,
  outcome with how long it holds, approver; survives restarts, unlike the old *Recent decisions*). Approvals record
  `approver` (the username) and `grant` (10 min, 15 min, until 14:20, always, blocklist) as their own fields –
  searchable (`approver:mwa`) and a filter in Logs → Audit; older entries are read from their detail text). The audit table moved to *Logs → Audit*,
  and the ⚠ badge for flagged entries now sits next to *Logs*.
- One implementation (`tclib.audit_*`) writes, reads, searches and exports the log for `svc` and tentacontrol – the
  two copies are gone. Entry format: flat fields with `id`, `category`, `actor`, RFC 5424 `severity`, RFC 3339 `ts`
  (milliseconds, `+02:00`) and `origin_session/entry/tmux/job/by` instead of the nested `from`; older entries are read
  as before. `tclib.audit_syslog()` formats an entry as an RFC 5424 message (not sent anywhere – for a later SIEM
  module).
- Rotation: `data/control/audit.jsonl` moves to `data/control/audit/<UTC time>.jsonl` at 10 MB (was: one
  `audit.jsonl.1` at 5 MB); archives are kept `AUDIT_RETENTION_DAYS` (new, default 90, Settings → General).
- The Claude Code hook `tc-guard` now runs for every tool (`matcher: "*"`) and also with `INJECTION_GUARD=false`
  (then `tc-guard --no-scan`: logging only). It reports through `svc tool-report` (`svc guard-report` still works).
  A Bash call that is one plain `svc` command is left to `svc`'s own entry; anything chained to it (`svc …; curl …`,
  pipes, `$(…)`) is logged and scanned as a whole. tentacontrol's background `svc test` runs for the status dots are not
  logged (the *Test connection* button is, as an admin action).
- Claude's base rules: a tentacle only for its own task – Claude no longer uses a service or SSH host as a tool for
  something else (e.g. `ping` through `svc ssh` because the sandbox has none) without asking first, naming the tentacle
  and the command.
- Claude's instructions reviewed: `/inventory` and `/onboard` point to *Approvals* (not *Activity*), `tentaclai-egress`
  belongs to the stack Claude must never restart, "tentacles are always reachable" is no permission to use them, SSH
  `read` allows the status commands, the svc commands are a list, the Docker hosts table names the SSH host.
- Logs → Audit: each type has its own colour (tool, svc, network, job, admin, sign-in; system stays grey) – in the table,
  the detail row and the filters sidebar; green, amber and red stay with the outcome.
- An entry's action no longer repeats its target: `connect` (not `connect n8n.example:443`, the count of a 15-minute
  window shows next to it, `connect · 24×`), `ssh tar …`, `test`, `sync`, `started 0.20.0`, `terminal opened`;
  reads through `svc` log the command line without `svc` and the tentacle. Older entries keep their text.
- `./tentaclai.sh passwd` shows the username; `./tentaclai.sh passwd --username <name>` renames the account.
- `svc audit [n] [--since 24h|7d] [search]` takes the same search (`svc audit 50 type:network outcome:blocked`); the
  older `--category/--service/--decision/--actor` still work.

### Upgrade
- `git pull` in the stack directory, then `docker compose build` and `docker compose up -d` – all three images change
  (svc and the hook, the gateway, tentacontrol). Recreating `tentaclai` ends running sessions and Remote Control.
- Nothing to migrate by hand: tentacontrol moves an old `audit.jsonl.1` into `data/control/audit/` on start, and
  older entries keep working. Optional: `AUDIT_RETENTION_DAYS` in `.env` (default 90).
- Bookmarks of `/activity?…` filters: the audit log is now `/logs?…`.
- The admin password moves from `data/control/admin.hash` into `data/control/users.json` on tentacontrol's start (the
  old file stays as `admin.hash.migrated`). Open sessions stay signed in; the next page asks once for a username and an
  email. Until then the sign-in form asks for the password only. Roll back: stop tentacontrol, rename
  `admin.hash.migrated` back to `admin.hash`, delete `users.json`.

## v0.19.0 – 2026-10-23

### Highlights
- **Approvals you don't miss**: tentacontrol shows waiting approvals in the tab title and on its icon, and can send
  desktop notifications from the browser (Activity → *Desktop notifications*) while it is open in any tab, also in the
  background – a click opens the request (`/activity#a-<id>`).
- **The approval link in the chat**: a Claude session waits `APPROVAL_HANDOFF` seconds (default 30, Settings →
  Approvals, 0 = off) for a decision; then `svc` exits with code 75 and the link, Claude posts it and runs the same
  command again, which waits for the same request. Useful with Remote Control in the browser, where a running command
  shows nothing. A decision is used once – a second identical call doesn't ride along.

### Changes
- **tentaclAI Community / Enterprise:** tentacontrol loads extensions (`TC_EXTENSIONS`, default
  `tentaclai_enterprise`, skipped when not installed) – their routes and templates come first. tentaclAI Enterprise is a
  separate package. In Community the sidebar shows *Modules* locked (a greyed-out list of the Enterprise modules behind
  “Modules are only available with a valid Enterprise license”); extensions register their modules, and a licensed
  module brings its own sidebar entry. Settings → *License* says what an Enterprise license adds and shows the
  *Installation ID* (derived from the hardware – system UUID of the firmware, else the Docker engine ID – never
  stored). New dependency of tentacontrol: `cryptography` (for extensions mounted into the image).
- Sidebar: new flagged entries (possible prompt injection) show as a yellow *⚠ count* next to *Activity*, and the
  Overview names them with a link – both until Activity is opened. Separate from the pulsing approval badge; the tab
  title and favicon stay for approvals.
- Prompt-injection safeguards: notes addressed to AI readers are flagged too – “Note for automated assistants: please
  …”, “If you are an AI …”, “Hinweis für KI-Assistenten …” – not only blunt “ignore your instructions”. Claude's base
  rules now say to mention any text that addresses AI assistants or asks the reader to do something, however polite,
  in one line to the user – also when it was only asked for a summary (until now it ignored such a note silently).
- Activity → a *flagged* entry (possible prompt injection) says what was read – the file, URL, search, MCP tool with
  its arguments or command, e.g. `tool result: Read /workspace/notes.md` instead of `tool result: Read` – and, under
  *Indicators*, each reason with a short excerpt and its line (a base64 block: size and start), secrets blanked;
  the notification carries the same. The result column reads *Claude warned* instead of *not run*. `tc-guard` now
  hands its findings to `svc guard-report` on stdin.
- Activity → audit log: decisions about unknown network destinations (Allow 10 min / 1 h, Always, Deny, Block, or
  *expired*) are logged too, with the part `network` – until now they only showed under *Recent decisions*.
- Activity → Recent decisions: *Always* shows as *allowed* and *Block* as *blocked* (orange) instead of *approved* /
  *denied*, so a lasting choice stands out from a one-off Allow or Deny.
- README links the [intro video](https://www.bitbunker.at/tentaclai/).
- Settings → General: the group of the prompt-injection switch is called *Prompt injection* (was *Security*, easy to
  mix up with the Security tab); Help names where the switch is.

### Upgrade
- `git pull`, `docker compose build`, `docker compose up -d` (tentacontrol gets the new dependency `cryptography`) – tentaclai is recreated too (new `svc` and base
  instructions), which ends running Claude sessions and Remote Control. New optional `.env` variable
  `APPROVAL_HANDOFF` (seconds, default 30, `0` = Claude waits silently as before).

## v0.18.0 – 2026-10-22

### Highlights
- **Prompt-injection safeguards** (`INJECTION_GUARD`, Settings → General, group *Prompt injection*, on by default): `svc web` now frames
  pages as untrusted like mail; mail and web text lose what a reader can't see (zero-width, direction and Unicode tag
  characters, elements hidden by CSS / `hidden` / `aria-hidden`). Mail, web pages, `svc files cat|grep` and API
  responses are checked for text that tries to instruct Claude; a new Claude Code hook (`tc-guard`, `PostToolUse` in the
  root-owned managed settings) does the same for WebFetch, WebSearch, MCP tools and files Claude reads. A finding warns
  Claude next to the content, shows as *flagged* in Activity and sends the new notification *Possible prompt injection*
  (routed like approvals until you change it). A heuristic – it warns, it doesn't block; the hard limits stay
  `read`/`confirm`, the egress gateway and mail recipient lists.

### Upgrade
- `git pull`, `docker compose build`, `docker compose up -d` – both images change (`svc`, `tc-guard`, the managed
  settings and the instructions in `tentaclai`; settings, Activity and notifications in `tentacontrol`). Recreating
  `tentaclai` ends running Claude sessions and Remote Control.
- New optional `.env` variable `INJECTION_GUARD` (default on; `false` switches the cleaning, the scanning and the hook off).

## v0.17.0 – 2026-10-22

### Highlights
- **Export / Import** (Settings → Export / Import): the configuration as one JSON file – services, systems, SSH hosts,
  jobs, network rules, notifications, site rules and plain settings. No secrets: the file only names the variables the
  other side needs. Import shows a preview (new / changed / same / invalid, with a diff), you pick the entries; an
  overwritten file keeps a `.bak-…-import`, new jobs start paused, new channels disabled, missing variables can be
  filled in right after.
- **Service templates:** “Template” on a service page downloads it as a template (own variables → `EXAMPLE_…`, the
  internal domain → `{{DOMAIN}}`, plain credentials left out); Services → *Import a template …* saves one to
  `local/templates/`.

### Upgrade
- `git pull`, `docker compose build control`, `docker compose up -d control` – only tentacontrol is recreated.

## v0.16.0 – 2026-10-22

### Highlights
- **Clearer access names:** `read` / `write` / `confirm` instead of `ro` / `rw` / `confirm` everywhere – UI, service
  templates, `svc` output, the audit log and Claude's instructions. The old names keep working; tentacontrol rewrites
  them in `services/*.json` and in SSH hosts (`# tentaclai: access=`) on start, with a backup `*.bak-<date>-access`.
  An unknown value still counts as `read`. Older audit entries are shown with the new names in Activity.
- **A more useful audit log:** a failed write records its last two error lines (secrets blanked, also in `svc audit`);
  search plus filters by time (last 24 h by default, 7 / 30 days, any time) and origin (Claude sessions, jobs, one job,
  tentacontrol / host), reset with one click;
  the origin links to the job run or the terminal; who approved a write or why it was blocked shows under the decision.
  Long actions and errors collapse to one line (click for the full text), and the table fits the page.

### Changes
- Network → Seen: click a column header to sort (destination, rule, last result, connections, last) – again to reverse;
  the choice is remembered in the browser.
- `svc mail` takes the mailbox address instead of the service name (`svc mail info@example.com list`) – it must belong
  to exactly one service; `svc mail` and the catalog list the address of every mail service.
- *Another mailbox on this server* shows which system the new mailbox joins (the one of the source service).
- Long sessions: Claude's status line shows how full the context window is (`ctx 42 %`, yellow from 60 %, red with
  `→ /compact` from 80 %), and a new base rule has Claude suggest `/compact` once in a long session, where a topic ends
  (not in jobs).
- Removed: migrations for installations before v0.11 (Claude's home move from v0.4, the `# tentaclaude:` marker,
  dropping `compose.generated.yaml` from `COMPOSE_FILE`, the hint for docker `"mode": "socket"`) and unused code.
- Dependencies: tentacontrol and the egress gateway run on Python 3.15, Apprise 2 is allowed; CI on
  `actions/checkout` v7 and `actions/setup-python` v7, tests allow pytest 9.

### Upgrade (from v0.15.0)
`./tentaclai.sh update`, `docker compose build`, `docker compose up -d` – all three images changed (svc, Python 3.15);
recreating `tentaclai` ends running sessions and Remote Control. Coming from a version before v0.11: update to v0.15.0
first (`git checkout v0.15.0`, build, start once) – its one-time migrations are gone now.

Access names: nothing to do – on its first start tentacontrol rewrites `ro`/`rw` to `read`/`write` in `services/*.json`
and `ssh/config.d/*.conf` (log line `migration: access ro/rw → read/write in …`) and keeps each old file as
`*.bak-<date>-access`. Rolling back to v0.15.0 needs those backups (copy them back over the files): v0.15.0 treats the
new names as unknown, i.e. as read-only. Git working copies get the new `tentaclai.access` value on
the next `svc git sync`.

## v0.15.0 – 2026-10-22

### Highlights
- **Jobs that propose:** with *Propose actions* (read-only profile) a run only analyses and returns proposed changes –
  a title and exactly one `svc` command each (checked: no shell syntax, no `svc config`, nothing interactive). The run
  lists them with check boxes for 24 h; *Run selected* runs exactly the picked commands through `svc`, without Claude –
  `ro` stays `ro`, `confirm` asks as usual, a limited job stays limited. Notifications say how many proposals wait;
  `svc jobs <name>` shows them too.
  Proposals that wait for a decision show right below the run, without unfolding it.
  The badge next to *Jobs* counts them and pulses like the approval badge until they are run, discarded or expire
  (*Discard selected* / *Discard all*).

### Changes
- Mail services: *Mail address* field when adding one from a Mail template (name suggested from it, e.g.
  `mail-root-example`; login and sender filled in), **… → Another mailbox on this server** copies host, TLS, folders,
  access and system with own variables, and mail cards show the address under the name.
- Services: compact cards – one access chip per part, set variables as one key chip (missing ones stay named),
  two-line description (click for the full text), no "active" pill; Edit as pencil, Disable/Fetch/move in the … menu. Disabled cards are dimmed.
- Job list: the profile shows as *reads* (neutral), *writes* (purple, the tooltip lists what it writes to without asking
  and what asks first) or *proposes* – the same colours as the access labels on service cards; yellow is kept for what
  waits for you. The editor names the profiles *Reads only* and *Can write (like a terminal session)*; the stored values
  stay `read-only` / `standard`.
- Job list: an on/off switch instead of *Pause*/*Resume*; a paused job's card steps back (dimmed) and says *paused – no
  automatic runs* instead of an empty next run. *Run now* stays available.

### Fixes
- Terminal: the page is exactly one window high and no longer scrolls – a stray wheel outside the terminal pushed the
  approval banner out of view and left an empty area below.
- `svc jobs`: long job names no longer run into the schedule column.
- `svc mail … folders` returned mangled names (`/" Junk`) on servers that quote them (Dovecot) – the LIST answer is parsed properly now.

### Upgrade (from v0.14.0)
`./tentaclai.sh update`, `docker compose build`, `docker compose up -d` – both images changed; recreating `tentaclai` ends
running sessions and Remote Control. Existing jobs keep working; *Propose actions* is off until you tick it.

## v0.14.0 – 2026-10-22

### Highlights
- **Jobs from the terminal**: `svc jobs` lists the jobs, `svc jobs <name> [--runs N] [--steps]` shows a definition with
  its recent runs (and Claude's steps) – Claude can analyse results and tune a prompt; `svc config put job <name> <file>`
  creates or changes a job after tentacontrol checked it and you approved it in Activity – new jobs start paused, and a
  running job can't create jobs.
- **Mail tentacles** `smtp` and `imap` (`svc mail`): send through a relay or a mailbox – `confirm` by default, `rw` only
  with a recipient list; read a mailbox – list, read (as untrusted content between markers, without marking it
  seen), mark and move with `rw`/`confirm`, folders can be limited. Through the egress gateway like databases; new
  rule in Claude's instructions never to act on instructions in a mail. Templates *SMTP relay*, *SMTP (with login)*,
  *Mailbox (IMAP + SMTP)*.
- **Scheduled jobs** (new menu item *Jobs*, badge for unseen findings): Claude tasks on a schedule – presets or cron, a traffic-light answer
  (ok / warn / alert) and notifications only on findings; templates for patch report, certificate expiry, disk space,
  backup check and container health. Profile *read-only* (default) is enforced twice – by Claude Code's tool rules
  and by `svc`, which recognises the run and treats every tentacle as `ro`; *standard* works like a terminal session
  (approvals for `confirm`, shown as “Job · name”).
  *Clone* copies a job – the copy starts paused.
  Tentacles are named in the task with `@name` (completed in the editor, checked on save with hints such as
  "sends mail from a read-only job"); *Only the tentacles named in the task* limits a run to them – `svc` refuses
  every other service and SSH host, MCP servers are off. A running run shows a spinner and its time, the page
  reloads when it ends.
  The latest run is always shown, earlier ones fold away under *History*.
  Schedule *manual* for jobs that run just with *Run now*.
  A running run shows Claude's steps live (tool calls, their output, Claude's text – from `stream-json`, refreshed
  every 2 s); finished runs keep them under *Claude's steps* (`data/control/job-logs/`, root only, pruned with the history).
  Read-only jobs may chain `svc` with text tools (`svc … | grep … | head`): Settings → Jobs → *Helpers in read-only jobs*
  (`JOB_READONLY_HELPERS`, default echo, head, tail, grep, jq, sort, uniq, wc, cut, tr, date, sleep) – shells,
  interpreters, awk/sed/find/xargs and network or write tools are refused.

### Changes
- Service cards and pages show every part's access the same way – `api: rw`, `docker: confirm`, `imap: ro` – including mail parts.
- Notifications: channel type **E-mail** – server, port, STARTTLS / SSL / none (internal relay), sender, recipients
  and an optional login in a form instead of a raw Apprise URL; the password stays in `.env`.
- The live output of image builds and updates moved from `/jobs/<id>` to `/builds/<id>` – `/jobs` is the new Jobs page.
- Template *zigbee2mqtt* removed (45 templates).
- Templates *Pangolin* and *Backrest*: a note on testing – Pangolin's `GET /` answers without the key (use
  `/org/<orgId>/sites`), Backrest's API has no GET that checks the login.

### Fixes
- `svc mail … list` shows when the server received a mail (IMAP INTERNALDATE, with time zone) instead of the sender's Date header.
- `svc mail … move` refused on Dovecot (Mailcow) with "no IMAP MOVE": the server lists MOVE only after the login, and
  svc looked at the list from before it. It asks again after the login now; the sandbox test moves a mail too.

### Development
- `test-sandbox.sh`: a GreenMail SMTP/IMAP server (send, refused recipient, list, framed read, seen flag, mark, move,
  read-only job can't send); scheduled-job checks (read-only marker, standard writes, scope limits, forged markers,
  `svc config put job` with approval, `svc jobs`).

### Upgrade (from v0.13.0)
`./tentaclai.sh update`, `docker compose build`, `docker compose up -d` – both images changed (svc recognises job
runs, mail, `svc jobs`); recreating `tentaclai` ends running sessions and Remote Control. Jobs start empty. The new
notification events *Job finding* and *Job failed* go to the channels that get *Approval needed* until you change them in
Notifications. New optional `.env` variable `JOB_READONLY_HELPERS` (empty = the defaults). Nothing to migrate; to roll
back, check out `v0.13.0` and rebuild – `data/control/jobs.json`, `job-history.json` and `job-logs/` are then unused.

## v0.13.0 – 2026-10-21

### Highlights
- **New area *Claude*** – everything that steers Claude in one place, in tabs: **Instructions** (a diagram of what
  Claude reads every session and what it looks up when needed, an editor for the site rules `local/CLAUDE.md` with
  backup, the generated `CLAUDE.md` to view), **Memory** (what Claude noted for itself – view, delete entries),
  **Models**, **Skills**, **Usage** (moved from Settings) and **settings.json** (Claude Code's own settings without
  the parts the other tabs manage; secret-looking env values masked, JSON checked, last 5 versions kept).
  *Settings* keeps tentaclAI itself: General, Notifications, Security.
- **Approvals on every page:** a banner above each page (but Activity) shows pending approvals with Approve / + 15 min /
  Deny (network: Allow 10 min / Deny) – no need to switch to Activity.

### Changes
- Services and Systems: the create forms are folded away behind *Add service* / *Add system* buttons in the header.
- Every page has a small **?** in its header that opens the matching part of Help (replaces the *Help* button on
  Services); the *Add …* button comes first everywhere and stays on the right when the subtitle is long. Network:
  small **?** next to *Mode* and *IP targets*, and Help has its own *Network* section (mode, IP targets, rule order).
- Topology: the legend just says *SSH host* (the colors are explained in Help).

### Fixes
- Redaction: *key* only counts as a name part of its own (`API_KEY`, `key_file`, `apikey`) – labels like
  `…keycloak….command` stay readable.
- `local/CLAUDE.md` keeps its last 5 backups (svc and tentacontrol), not every one.
- **Site rules were not loaded:** `svc config put local` wrote `local/CLAUDE.md` with mode 0600 (svc inherits the
  entrypoint's umask 077), so Claude's `@` import skipped it without a word. svc writes it 0644 now and the
  entrypoint repairs the mode on start.
- tentacontrol cached a failed lookup of the sandbox's address for 5 s – right after the sandbox started, its
  first requests counted as "anyone else" and reached the login page. Misses are not cached any more, and any other
  address from the sandbox's network (subnet read from Docker) now counts as the sandbox – a failed lookup gives less
  access, not more.
- Safari showed the SVG favicon without its background (a bare red octopus): only the PNG icons are offered now.
- Pages with a wide tab bar no longer get wider than a phone screen – the tabs scroll.
- Usage: Claude Code's hint *28 % See what fills your context* showed its number alone on the right – it reads
  *28 % for context in every request – check with `/context`* now. A limit at 100 % shows a note that requests now
  run on extra usage (credits) if it is on – Claude Code's `/usage` doesn't report the credit balance.
- Browser terminals left their `docker exec` process running when the connection dropped – one stale tmux client per
  reload, and tmux sized Claude's window to the smallest of them. Closing a terminal now hangs its process up
  (a tmux client detaches, Claude keeps running).
- Safari showed a stand-in tab icon: it ignores SVG favicons. PNG icons (32 px, 180 px `apple-touch-icon`) are
  served too, also at `/favicon.ico` and `/apple-touch-icon.png` without login.
- Text in the browser terminal could not be selected on a Mac: tmux takes the mouse, and xterm.js only lets Shift + drag
  through on other systems. Option + drag selects on a Mac now; Cmd+C (Safari never fired xterm.js's own copy event) and `Ctrl+Shift+C` copy.
  A plain drag selects in tmux or in Claude's full-screen view: the copy (OSC 52, tmux now passes Claude's on with
  `set-clipboard on`) reaches the clipboard – right away, or on Cmd+C in Safari.
- The sidebar's approval badge stayed after the last decision (an empty answer was kept by the page).
- The favicon changed from page to page: `/favicon.ico` redirected to the login – it serves the logo now.
- **Plain `http://` from the sandbox now goes through the egress gateway:** only `HTTP_PROXY`/`HTTPS_PROXY` were set,
  but curl reads the lower-case `http_proxy` for `http://` URLs – such requests failed at name resolution instead of
  reaching the gateway (and asking for approval). Both spellings are set now. `svc` was not affected.
- `tc-scan` stopped on hosts with container labels like `…keycloak….command` holding escaped quotes: `svc`'s
  redaction cut the value at the first `\"` and left invalid JSON. `inspect` output is now redacted value by
  value as JSON (always valid), and `tc-scan` skips unreadable inspect output instead of aborting.

### Development
- `test-sandbox.sh`: the rename check cleans the last run's copies – it failed on a kept REUSE stack.
- CI: image layers come from the GitHub Actions cache (`TC_BUILD_CACHE=gha` in `test-sandbox.sh`) instead of a full
  build on every run.
- `test-sandbox.sh`: checks slower than 2 s print their time; refusal checks test the gateway's `403` instead of
  `000` (a timeout gives `000` too); the plain-http case is tested; a REUSE run waits until the gateway forgot a leftover
  test service (that wait was 30 s per run).

### Upgrade (from v0.12.0)
`./tentaclai.sh update`, `docker compose build`, `docker compose up -d` – both images changed (svc, entrypoint, tmux
settings, tentacontrol); recreating `tentaclai` ends running sessions and Remote Control. Nothing to migrate: the
entrypoint makes an existing `local/CLAUDE.md` readable for Claude again.

## v0.12.0 – 2026-10-21

### Highlights
- **Where a request comes from:** approvals in Activity, their notifications and the audit log show the requesting
  Claude session – e.g. *Remote Control · “Mailcow prüfen”*, *Claude terminal · /workspace*, *Onboarding patchmon*,
  *shell (no Claude session)*. sudo keeps exactly four variables for this (`CLAUDE_CODE_SESSION_ID`,
  `CLAUDE_CODE_ENTRYPOINT`, `TMUX`, `TMUX_PANE`) – never the session's access token; `svc` and tentacontrol check every
  value. The session title comes from the session files tentacontrol already reads for Usage. It is a hint for you,
  not a security feature: Claude controls these values.

### Fixes
- Usage: Claude Code's `/usage` now lists several periods (last 24 h, last 7 days) with tips – they ran together into
  one list. Each period is its own block now, with the share of each tip and the top skills / MCP servers.

### Upgrade (from v0.11.0)
`./tentaclai.sh update`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and
Remote Control (needed for the new sudo rule).

## v0.11.0 – 2026-10-21

### Highlights
- **Two-factor sign-in for tentacontrol** (Settings → **Security**): a code from an authenticator app after the password
  (TOTP, RFC 6238 – no new dependency). Set up with a QR code; 10 one-time **recovery codes** for a lost phone (stored as
  hashes, a sign-in with one sends a notification); **“Trust this browser”** skips the code for 30 days – signed cookie
  plus a server-side list, so single browsers or all can be revoked. Switching off needs the password and a code; on
  the host `./tentaclai.sh reset-2fa`. A password reset also revokes the trusted browsers. Optional – off until you
  switch it on.

### Changes
- **Docker hosts run over SSH only** – the `socket` mode for docker services is gone. It mounted the host's Docker
  socket into the sandbox, which made Claude root on the host and undid the privilege separation (`.env`, SSH key).
  Every docker host, the tentaclAI host too (an SSH host for `host.docker.internal`), is reached through `svc` over SSH.
  `svc` refuses an old `"mode": "socket"` entry with a hint, the service page marks it *not usable*.
- With it go `compose.generated.yaml` (and its comparison in the *Apply now* hint), the Docker CLI in the sandbox image
  (1.47 → 1.26 GB), the template *Docker host (local, socket)*, the per-host Claude terminal tabs and
  `./tentaclai.sh host`. `./tentaclai.sh init` points to SSH hosts instead of offering a socket service.
- tentacontrol keeps the Docker socket – it runs the sandbox; *Docker socket proxy* is off the roadmap.

### Upgrade (from v0.10.0)
`./tentaclai.sh update`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and
Remote Control. Two-factor sign-in stays off until you set it up under Settings → Security. On its first start tentacontrol removes `compose.generated.yaml` from `COMPOSE_FILE` in `.env` (the
stale file can be deleted). **If you used a docker service in `socket` mode:** add the host under Tentacles → SSH hosts
(this host: hostname `host.docker.internal`, a user allowed to run docker or a sudo prefix), then set `"mode": "ssh"`
and `"ssh_host": "<alias>"` in the service and remove `"socket"`.

## v0.10.0 – 2026-10-21

### Highlights
- **Rename a service**: *Rename* on the service page – the file, `svc <name>` calls in its examples and notes, and for
  git services root's mirror and Claude's working copy (`/workspace/repos/<name>`) move together; `svc sync` updates
  the catalog and MCP entries. Tokens, system and rules stay.

### Security
- **The sandbox can no longer reach tentacontrol's admin UI:** tentacontrol shares the sandbox network for `svc`'s
  approvals, which also exposed the login (behind it: the Docker socket) and the gateway's token-less
  `/internal/egress/*` endpoints – Claude could have created network approvals itself. Requests are now checked by
  their source: the sandbox gets only `svc`'s endpoints (with its token), the gateway only the egress endpoints,
  nobody else the egress endpoints; the web terminal refuses the sandbox too.
- **Secrets of other services are blanked** in free read-only output that `svc` passes on: `docker … inspect`
  (container env, labels), `compose … config` (interpolated `.env` values) and `systemctl show|cat` – values of
  secret-looking names and passwords in URLs become `[redacted by svc]`.
- tentacontrol no longer follows symlinks in Claude's session directory (usage, skill descriptions).
- `svc` keeps the `.env` values to itself instead of putting them into its process environment – ssh, docker, compose
  and git no longer inherit every service token (a local `docker compose` would even have preferred them over a
  stack's own `.env` values).
- Credentials are recognised by where a service uses them (`auth`, `headers`, MCP `env`, `password`/`token` fields),
  not only by their name – e.g. `NETBIRD_PAT` was shown in clear on the service page and in Settings. More name
  hints too (`PASS`, `PAT`, `AUTH`, `CREDENTIAL`, `PRIVATE`, `COOKIE`).
- Escaped the error output of the service page's test button.

### Fixes
- `./tentaclai.sh update` goes to the **latest release** instead of the newest commit on `main` (`--main` for that);
  the Updates page announces releases, so both now agree.
- The egress gateway's list of seen destinations is capped (2000 entries, unused for 90 days are dropped) – it grew
  without limit.
- A change on Settings → Skills/Models that couldn't be applied said "the sandbox is not running" even when it ran an
  older version – the message now names the version and says to recreate it.
- README: DNS is not a way out – the sandbox resolves only the stack's containers.
- A second service created from the same template shared the first one's token variables (most templates use fixed
  names like `HA_TOKEN`) – entering a token for one silently changed the other. It now gets its own variables
  (`PATCHMON_TOKEN_KEY` → `PATCHMON_SKYNET_TOKEN_KEY`); services of a different kind keep sharing on purpose (e.g.
  `GH_TOKEN` for the GitHub API and a git repo). The service page shows which other services use a variable.
  Existing pairs are not changed automatically – check the *Tokens & variables* card.
- Egress gateway: a service that was just enabled (or whose last token was just set) asked for a network approval
  on its first use – the gateway only re-reads its policy every 15 s. Before it asks, it now re-reads the policy once
  and decides again.

### Changes
- Service templates fill in **`example.com`** instead of the site's `TC_DOMAIN` – no guessed addresses; the service page
  warns as long as `example.com` is still in a service. `TC_DOMAIN` now only suggests the tentacontrol address in
  `./tentaclai.sh init`.
- Template **PatchMon**: the integration API takes a token *key and secret* as Basic auth under `/api/v1/api` –
  the template had a single bearer token and the wrong base URL. Existing PatchMon services: switch `auth` to
  `{"type": "basic", "user": "${PATCHMON_TOKEN_KEY}", "password": "${PATCHMON_TOKEN_SECRET}"}`, `base_url` to
  `…/api/v1/api` and `test_path` to `/hosts`.
- Services without a `test_path`: the *Test API* card warns that `svc test` only checks `GET /` (often a 404, or a
  check that passes without the token), pre-fills the path from the template of the same name and saves it with
  *Save as test path*; `svc test` prints the same hint.
- Settings → Skills: `inventory` and `onboard` are marked *required by tentaclAI* and can't be switched off – the
  inventory terminal and *Onboard with Claude* start them; an "off" skill can't even be called as `/command`.
  */command only* is allowed (verified: it still runs when started as `claude /inventory`).
- tentacontrol asks Claude Code for connectors and skills once an hour and right after a sign-in (was: connectors every
  10 minutes, skills every 30) – `claude mcp list` health-checks every MCP server each time. *Check* still works at once.

### Development
- CI: `actions/checkout@v5` and `actions/setup-python@v6` (Node 20 actions are deprecated); Dependabot also watches the
  GitHub Actions, the egress image and `tests/requirements.txt`.
- `scripts/release.sh` pushes main and waits for the green GitHub `checks` run of that commit before it creates the
  release commit, tag and release – a red CI stops it before anything is tagged.
- tentacontrol's `main.py` (1550 lines) is split: app, middleware and background loops stay (165 lines), pages and
  endpoints live in `control/app/routes/` (one router per area), shared helpers in `web.py`, the small JSON state
  files go through `jsonstore.py`. The gateway's rule order is one function (`tclib.egress_rule`), shared with the
  Network page – they disagreed on allowlist vs. tentacle.
- Stage 1 renders every parameterless page found in the app's routes – no hand-kept list; stage 2/3 check a few pages
  and the vendored assets in the real container.
- `scripts/test-quick.sh`: test packages in `~/.cache/tentaclai-test-deps` (outside the stack, so backups skip them),
  the dummy stack in `/tmp` is removed after each run, `httpx2` for Starlette's TestClient (no deprecation warning left).

### Documentation
- README: configuration table complete (`EGRESS_*`, `CLAUDE_TELEMETRY`, `UPDATE_*`, `NOTIFY_URL_*`), repository layout
  with `egress/`, `routes/`, `scripts/`, `tests/` and the three `data/` directories, the Usage page, corrected: where
  the Claude login lives (`data/claude`), `HOST_DOCS` is referenced (not imported), DNS is no way out.
- Help: services have seven parts (not four), test path, rename and shared token variables, the Usage page, the new
  security measures, more troubleshooting; CONTRIBUTING: the three test stages, `release.sh`, template guidance.

### Upgrade (from v0.9.1)
`./tentaclai.sh update` (or `git pull`), `docker compose build`, `docker compose up -d` – all three containers changed.
**Recreate `tentaclai`** (ends running sessions and Remote Control): the `svc` fixes – blanked secrets, no tokens in
child processes – only take effect in a new sandbox container. No `.env` changes. Services created from older templates
may lack `test_path` – their service page now says so and suggests the template's value. From this release on
`./tentaclai.sh update` goes to the latest release tag (`--main` for unreleased changes). Developers: the old
`.cache/test-deps` in the stack directory can be deleted.

## v0.9.1 – 2026-10-20

### Fixes
- tentacontrol's regular `claude -p /usage` and `/context` calls no longer leave a session file behind each time
  (`--no-session-persistence`); sessions without a single reply are no longer listed on the Usage page.
- tentacontrol starts its background tasks through FastAPI's `lifespan` instead of the deprecated `on_event`.

### Development
- `scripts/release.sh X.Y.Z "subtitle"`: checks (main, clean, not behind, Unreleased with Upgrade part), stage 1 and
  the full sandbox test, then CHANGELOG/VERSION, commit, tag, push and the GitHub release from the changelog notes;
  `--dry-run` changes nothing.

### Upgrade (from v0.9.0)
`git pull`, `docker compose build control`, `docker compose up -d control` – only tentacontrol changed, running Claude
sessions are not affected. Optional: session files that only hold a `/usage` or `/context` call can be deleted from
`data/claude/.claude/projects/` (they contain no reply).

## v0.9.0 – 2026-10-20

### Highlights
- **Settings → Models**: model and effort per task – *Default* (every session, terminal and Remote Control),
  *Subagents* and the set-up commands */inventory and /onboard*; aliases (`fable`, `opus`, `sonnet`, `haiku`) or an own
  model id, *Standard* = Claude Code decides. Applied right away (new sessions) and on every container start: `model`,
  `effortLevel` and `env.CLAUDE_CODE_SUBAGENT_MODEL` in Claude's `settings.json`, `model:`/`effort:` in the commands'
  frontmatter. The page also shows the usage per model of the last 14 days.

### Changes
- **Behaviour change:** subagents and `/inventory`·`/onboard` run on **Sonnet** by default (less plan quota for
  searches and set-up). The default model of the sessions stays Claude Code's choice. Back to the old behaviour:
  Settings → Models → *Standard*.

### Fixes
- Settings → Skills: the *Mode* select was squeezed to its arrow; descriptions of skills with a colon in the name
  (`anthropic-skills:pdf`) were missing.
- Usage: the billing line showed Claude Code's "Warning: … blocked by enterprise policy" line instead.

### Development
- Tests in three stages: `scripts/test-quick.sh` (no Docker, seconds – syntax, ShellCheck, pytest unit tests for tclib,
  parsers and connector/skill state, every tentacontrol page rendered with dummy data; also the CI `checks` job),
  `REUSE=1 ONLY=<sections> scripts/test-sandbox.sh` (targeted, reuses the test stack, rebuilds only changed images) and
  the full `scripts/test-sandbox.sh` before every release. Waits poll instead of sleeping; the gateway's policy interval
  is configurable (`EGRESS_REFRESH`, default 15 s, 1 s in the tests). Full run: 98 s → 29 s.

### Upgrade (from v0.8.0)
`git pull`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and Remote
Control. Nothing to migrate; subagents and the set-up commands use Sonnet afterwards (see Changes).

## v0.8.0 – 2026-10-20

### Highlights
- **Settings → Skills**: every skill of Claude Code and the claude.ai account with its size in tokens, set to *On*,
  */command only* (`user-invocable-only`: only when called as `/name`) or *Off*. Written as `skillOverrides` into
  Claude's `settings.json` – right away and on every container start. Skills are found with `claude -p /context`
  (no model call) every 30 minutes or with *Check*; switched-off ones are remembered in `data/control/skills.json`.
  The defaults of v0.7.1 (sandbox-useless skills off) stay; entries of your own for other skills are kept.

### Upgrade (from v0.7.1)
`git pull`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and Remote
Control. Nothing to migrate.

## v0.7.1 – 2026-10-20

### Fixes
- **claude.ai connectors were not denied**: `/etc/claude-code` was created with mode 700 (umask of the entrypoint), so
  Claude Code could not read the managed settings and ignored them ("policies … are NOT in effect"). The directory is
  now 755; the file stays root-owned and read-only for Claude.

### Changes – less context per request
- Skills that make no sense in a headless sandbox (Office files, Artifacts, browser/computer use, morning brief …) are
  switched off by default via `skillOverrides` in Claude's `settings.json` – entries set by the user are kept.
- The sandbox instructions (`CLAUDE.base.md`, SSH host section) are about a third shorter: the command table points to
  `svc help` instead of repeating it; all rules stay. New section *Keep context small* (bundle read-only calls, filter
  outputs at the source, narrow MCP calls).
- `/inventory` and `/onboard`: fewer turns – bundled read and test calls, the scan is read once from a file, the
  summary comes with the first question round, no duplicate `cat`/backups, OpenAPI specs only as a path list.

### Upgrade (from v0.7.0)
`git pull`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and
Remote Control. Afterwards switched-off connectors are really off in the sandbox.

## v0.7.0 – 2026-10-20

### Highlights
- **Notifications** – Settings → *Notifications*: channels through Apprise (presets for **ntfy** and **webhook**, any
  other Apprise URL – Telegram, Discord, Slack, Teams, e-mail, Home Assistant …), a matrix *event × channel*, quiet
  hours (only urgent events) and dedupe. Events: approval needed, approval expired, blocked (ro write, blocklisted
  destination, IP target), Remote Control down, Claude signed out, container stopped, update available. Channel URLs
  are stored in `.env` (`NOTIFY_URL_…`), never shown. *Send test* per channel.
- **Usage** – the Claude Code card on the overview shows the plan limits (session and week, account-wide) as bars;
  details on the new *Usage* page: what contributes, tokens per day, sessions of this sandbox, models. Limits come from
  `claude -p "/usage"` every 10 minutes (no model call), token totals from the local session files (usage fields only).
  Notification event *Quota running low* at 80 %. Each reply is counted once (Claude Code stores streamed replies
  more than once).
- **claude.ai connectors as built-in tentacles** – connectors of the signed-in account (Google Drive, Claude Docs …)
  are listed under Tentacles → Services and are **off by default**: they reach the outside directly, not through svc.
  Switched-off connectors go to `deniedMcpServers` in the sandbox's root-owned `/etc/claude-code/managed-settings.json`;
  new ones are detected every 10 minutes and start disabled. Also saves context in every request.

### Changes
- The host documentation (`HOST_DOCS`) is referenced in Claude's instructions instead of imported – Claude reads it
  when it works on the host; saves ~4.6k tokens of context in every request.
- Login: the password reset hint sits behind *Forgot the password?*.
- UI: an empty response never wipes the element that sent it; the `hidden` attribute always wins; inputs without a type,
  number and time fields look like all others; checkboxes in the accent colour.

### Upgrade (from v0.6.1)
1. `git pull`, `docker compose build` (tentacontrol gets the `apprise` package), `docker compose up -d` – recreating
   `tentaclai` ends running sessions and Remote Control (or *Apply now* in tentacontrol).
2. **Behaviour change:** claude.ai connectors (Google Drive, Claude Docs …) are **off** in the sandbox after the upgrade.
   If Claude should use one, switch it on under Tentacles → Services → *Built-in · claude.ai connectors*.
3. Optional: add notification channels under Settings → Notifications. Their URLs are stored in `.env` as
   `NOTIFY_URL_<ID>`; nothing to set by hand.
4. Claude's instructions no longer import the host documentation – it is still available at `/etc/tentaclai/host-docs.md`.

## v0.6.1 – 2026-10-20

### Changes
- **Tab completion for `svc`** in the sandbox shells: commands, service names per part (docker, db, git, web, files),
  SSH hosts, sub-commands.
- The *Apply now* banner also appears when a newer sandbox image was built. Terminal tabs: *Claude · RC*,
  *Shell · svc list*. Wording no longer homelab-specific.

### Upgrade (from v0.6.0)
`git pull`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and Remote
Control (or use *Apply now* in tentacontrol, which now also appears when a newer image was built). No `.env` changes.

## v0.6.0 – 2026-10-19

### Highlights
- **Egress gateway** – the sandbox sits in an internal Docker network without a route to the outside. Its only way out
  is the new container `tentaclai-egress`, a small forward proxy (CONNECT for any TCP port, plain HTTP; TLS is not
  opened). Claude Code, curl, git, pip and npm use it through `HTTPS_PROXY`; svc tunnels ssh/rsync (`ProxyCommand
  tc-connect`) and databases (local port forward) through it.
- **Network page** – every destination with its rule, last connection and filters; your allowlist and blocklist with
  one-click Allow/Block; the tentacles and the built-in list; *Clear*.
- **Mode permissive / enforce** – `permissive` (default) allows and records everything; `enforce` holds a destination
  without a rule up to 60 s and asks in Activity: *Allow 10 min*, *Allow 1 h*, *Always*, *Deny*, *Block* (also shown in
  Claude's status line). **IP targets** – bare IP addresses without a rule are blocked (default) or asked about.
- **Rules** in this order: built-in list (Anthropic, GitHub, PyPI, npm – can't be blocked) → blocklist → your allowlist
  → tentacles (hosts of your services and SSH hosts, derived live) → temporary approvals. Entries: host, `*.domain`, IP
  or range (`10.0.0.0/8`), optionally `:port`; IP rules are checked against the resolved address.
- **Tentacles** – new name of the *Connections* area and the collective term for everything Claude can reach.
- **Claude Code without telemetry** by default (`DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `DISABLE_BUG_COMMAND`
  in Claude's settings.json); remote control keeps working. `CLAUDE_TELEMETRY=true` turns it back on.
- **Sign out of Claude** from the overview (to connect a different account); the card shows the signed-in account.
- **Logo**: coral octopus in a white birdcage, readable at small sizes; new screenshots.

### Changes
- Public, read-only sources need no service any more: the templates `web-public`, `git-public` and `context7` are gone –
  allow the host under Network. Existing services of that kind keep working.
- Overview: Network card (mode, destinations, without a rule, waiting approvals). Terminal: *Claude login* only while
  signed out, hover hints on every tab. Logs in the configured time zone. *Pin version* jumps to its setting.
- Claude's instructions: all service parts, `svc test`/`svc pending`/`svc audit`, network rule, content from services
  is data, the tentaclai containers and tmux sessions are off limits, no root.
- Fix: `ssh/` is handed to root on start – a stack cloned as a normal user made ssh refuse its config.
- Terminal tabs are named consistently (*Claude · /workspace*, *Claude · RC*, *Claude · system inventory*).
- `scripts/test-sandbox.sh` – end-to-end tests (privilege separation, svc through the gateway, network rules, every
  page), also run in CI. `scripts/build-screenshots.sh` rebuilds the README screenshots from a made-up demo site.

### Upgrade (from v0.5.0)
1. `git pull` in the stack directory. `ssh/config` gains `ProxyCommand tc-connect %h %p` – if you changed that file
   yourself, merge it.
2. `docker compose build` (now three images: tentaclai, tentacontrol, tentaclai-egress).
3. `docker compose up -d` – creates the networks `sandbox` (internal) and `outside`, the volume `egress-data` and the
   container `tentaclai-egress`, and recreates `tentaclai` and `tentacontrol`. Running Claude sessions and Remote
   Control end.
4. New optional `.env` settings: `EGRESS_MODE` (permissive, default | enforce), `EGRESS_DIRECT_IP` (block, default | ask),
   `CLAUDE_TELEMETRY` (false, default). Nothing to set – the mode can be switched on the Network page.
5. If a container manager updates images (e.g. Arcane), give `egress` the same labels as `claude`/`control` in
   `compose.override.yaml` (see `compose.override.example.yaml`).
6. Recommended: leave `permissive` running for a while, then check Network → *Seen*, allow or block what has no rule,
   and switch to `enforce`.

Rollback: `git checkout v0.5.0`, `docker compose build`, `docker compose up -d --remove-orphans` (removes the gateway;
the sandbox gets its normal network back).

### Known issues
- DNS is not filtered yet: the sandbox can still resolve names.
- Programs that ignore `HTTPS_PROXY` can't connect from the sandbox (by design).

## v0.5.0 – 2026-10-19

### Highlights
- **Status line in Claude's terminal** – every Claude session shows `▥ tentaclAI · safely caged`, model and directory,
  and – refreshed every 5 seconds – pending approvals with a link to Activity. Set in `~/.claude/settings.json`
  only when you have no status line of your own. `svc pending` lists pending approvals and active grants.
- **New logo and slogan** – the octopus sits in a birdcage, its arms reach out: “Long arms, one brain – safely caged.”

### Upgrade (from v0.4.1)
`git pull`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and Remote
Control. No `.env` changes. The new logo may need a hard reload in the browser (cached favicon).

## v0.4.1 – 2026-10-19

### Changes
- Approvals are announced before they block: Claude tells you what it is about to request (and where to approve it)
  before running a write on a `confirm` part, and uses the maximum Bash timeout (10 min) for such commands.
- svc prints a direct link to Activity (`CONTROL_URL/activity`) and a reminder every minute while it waits.

### Upgrade (from v0.4.0)
`git pull`, `docker compose build`, `docker compose up -d` – recreating `tentaclai` ends running sessions and Remote
Control. No `.env` changes. Claude sessions started before the upgrade keep the old rules until they are restarted.

## v0.4.0 – 2026-10-19

### Highlights
- **Privilege separation in the sandbox** – Claude now runs as the unprivileged user `claude`. `.env`, the SSH key, the
  service files, git credentials and the audit log belong to root; `svc` (and `tc-scan`) run as root through a single
  sudo rule and are Claude's only way to services. `ro` / `rw` / `confirm` are now enforced, not just guard rails.
- **Client tools as `tcrun`** – curl, psql, mariadb and stdio MCP servers run as a third user with only the secret
  they need; a shell escape from the SQL shell gets neither root nor `.env`.
- **MCP proxy** – MCP servers with tokens are registered as `svc mcp-proxy <name>` (stdio ↔ Streamable HTTP bridge
  with the headers added by svc); the tokens are no longer in Claude's `~/.claude.json`.
- **Git through a mirror** – working copies in `/workspace/repos` have no credentials; `svc git push|pull|fetch <repo>`
  move commits through a root-owned mirror (git bundles), with the repo's access mode and approval.
- **`svc ssh <host> [cmd]`** replaces plain `ssh`: access per SSH host (`confirm` by default, `rw`, `ro`), set in
  tentacontrol → Connections → SSH.
- **Approve + 15 min** – one click lets further writes of the same service part / SSH host run for 15 minutes
  (Activity → Active grants, revocable; never for `svc config put`).
- **Status commands over `svc ssh` without approval** – a fixed allowlist (`uptime`, `df`, `docker ps|logs|inspect`,
  `systemctl status`, `journalctl`, `ip a`, `ss` …, no shell syntax, no file contents) runs on every host, even `ro`.
- **`svc config put`** – Claude proposes service files (`/onboard`) and site rules (`/inventory`); every write needs
  your approval in Activity, the old file is kept as `.bak-…`.

### Changes
- The tmux session of the Claude terminal is now named `claude-workspace` (was `claude`); the overview lists sessions
  with readable names; the overview button “Workspace” is now “Claude terminal”.
- `.env` is no longer loaded into the sandbox environment (`env_file` removed) – only svc reads it.
- Claude's home is `/home/claude` (`data/claude`); root's home `/root` (`data/home`) keeps svc state only.
- Docker services in `ssh` mode always run `docker` on the host through ssh (no docker contexts) – `cp`/`build` paths
  are host paths.
- `svc <api> … -o file` can't write into the workspace any more (curl runs as `tcrun`) – redirect with `> file`.
- `gh` in the sandbox has no credentials; `GH_TOKEN` is only a variable for service files.
- Terminals in tentacontrol and `./tentaclai.sh` run as user `claude`; `./tentaclai.sh rootshell` opens a root shell.
- The container drops all capabilities except CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, KILL and AUDIT_WRITE.

### Upgrade (from v0.3.0)
1. `git pull` in the stack directory.
2. `docker compose build` (both images).
3. `docker compose up -d` – recreates **both** containers; running Claude sessions and Remote Control end.
4. Automatic on the first start: Claude's login, settings and history move from `data/home` to `data/claude`, file
   permissions of `.env`, `ssh/` and `data/` are tightened, `/workspace` is handed to the user `claude`, repos lose
   their credential helper, MCP servers with tokens are re-registered through the proxy. Nothing to do in `.env`.
5. In tentacontrol → Connections → SSH: check the new **Shell** column (`svc ssh` access per host, default `confirm`).
6. Recommended: rotate tokens Claude could read before this release (everything in `.env`, MCP headers).
7. `./tentaclai.sh` and Remote Control work as before; Remote Control may ask for the one-time confirmation again.

Rollback: `git checkout v0.3.0`, `docker compose build`, then move the home back before starting:
`mv data/claude/.claude data/claude/.claude.json data/home/` and `docker compose up -d`.

### Known issues
- A Docker service in `socket` mode is root on the tentaclAI host and can read the stack's secrets; its stacks
  directory is root-owned, so Claude edits it through `svc compose`/`svc docker` only. Prefer `ssh` mode.
- No egress filter yet – the sandbox can still reach the network.

## v0.3.0 – 2026-10-18

### Highlights
- **Access mode `confirm`** – writes of a service wait for your approval in tentacontrol → **Activity**
  (Approve / Deny, badge in the sidebar). Denied or no answer within 10 minutes = not executed.
- **Audit log** – every write through `svc` is recorded: automatic (`rw`), approved / denied / expired (`confirm`) and
  blocked (`ro`), without secrets. Filterable in Activity, `svc audit` in the sandbox.

### Changes
- Writes are: API calls other than GET/HEAD/OPTIONS, docker/compose commands that change something, SQL that is not a
  plain query (and the SQL shell), `svc files … push`, and `git push` (pre-push hook in every repository).
- `api` parts accept an optional `access` field (`rw` default, `ro`, `confirm`); access pills show `confirm`.
- Claude is instructed to report pending approvals and never to work around a denial.
- Guard rail, not a hard boundary: Claude runs as root in the sandbox; MCP calls are not covered (see Security in the README).

### Upgrade from v0.2.1
1. `./tentaclai.sh update` – or `git pull`, `docker compose build`, `docker compose up -d`. Both images change;
   recreating `tentaclai` ends running sessions and Remote Control.
2. Optional: set `"access": "confirm"` on service parts whose writes should need your approval
   (e.g. a docker host: `"docker": { …, "access": "confirm" }`).

No `.env` changes.

## v0.2.1 – 2026-10-18

### Highlights
- **`./tentaclai.sh update`** – update with one command: shows what's new (changelog incl. upgrade steps), pulls,
  rebuilds and asks before recreating each container; `--check` only shows what is new.
- **Status dot per service** on the service cards and pages – result of the last connection test (green / yellow =
  partly or token missing / red), cached for 10 minutes and refreshed when the service or `.env` changes.
- **Update notice** in the sidebar when a new release is out, with the release's upgrade steps on the Updates page.
- **TLS switch per service** – *Ignore TLS certificate errors* for devices with self-signed certificates.

### Changes
- **TLS:** `insecure_tls` now works for `api`, `web`, `git` (`http.sslVerify=false` for that repo only) and `db`
  (no certificate verification); cards show “TLS not verified”, `svc info` warns.
- **Update notice:** GitHub releases are checked every 6 hours; new settings `UPDATE_CHECK` (default on) and `UPDATE_REPO`.
- tentacontrol runs on Python 3.14.
- Dependabot: pip updates only when a version falls outside the allowed range; no Node major updates for the sandbox.

### Upgrade from v0.2.0
1. `git pull` in the stack directory.
2. `docker compose build` – both images (the sandbox's `svc` handles TLS for git and databases).
3. `docker compose up -d` – recreates both containers; recreating `tentaclai` ends running sessions and Remote Control.

No `.env` changes needed (`UPDATE_CHECK`/`UPDATE_REPO` are optional). From now on, `./tentaclai.sh update` does these steps.

## v0.2.0 – 2026-10-18

### Highlights
- **SSH hosts completely in the UI** – add with host key confirmation and one-time password key deployment, edit
  (incl. jump hosts, sudo, rename with references), remove with key revocation.
- **Connections** – Services, SSH hosts, Systems and Topology in one place with tabs; new Systems overview.
- **One shared implementation** (`lib/tclib.py`) for `.env`, services, systems and SSH hosts.
- **Safer repository** – CI checks and a pre-commit guard against committed site data and secrets.

### Changes
- The installed version is shown in the sidebar and on the Updates page (`VERSION` file in both images).
- **Connections:** Services, SSH hosts, Systems and Topology are one navigation item with tabs; new **Systems** overview page.
- **SSH hosts fully in the UI:** add (host key confirmation, key deployment with a one-time password, test), edit
  (host, user, port, jump host/ProxyJump, sudo, rename incl. references) and remove (optionally revoking the key).
- Connection tests always open a fresh SSH connection, so changed host keys or revoked keys show up immediately.
- **Shared logic in `lib/tclib.py`:** `.env`, `${VAR}`, services, systems and SSH hosts have one implementation used by
  `svc`, `tc-scan`, `claude-instructions` and tentacontrol (no behaviour change).
- **`ssh-host.sh`** is now a thin wrapper around `tentacontrol-ssh` (same logic as the UI): `list`, `add … [--jump <alias>]
  [--sudo | --sudo-cmd]`, `sudo`, `hostkey`, `remove [--keep-key]`, `test`. Both containers must be running.
- Docker builds use the repository root as context (`.dockerignore` whitelists `build/`, `control/`, `lib/`).
- Container logs are limited to 3 × 10 MB per container.
- **Checks:** GitHub Action (site data/secrets, Python and shell syntax, ShellCheck, JSON/YAML/Jinja) and an optional
  pre-commit hook (`git config core.hooksPath .githooks`).
- `svc docker <host> exec -it …` and `svc compose <host> <stack> exec …` work interactively on SSH hosts with sudo
  (svc requests a terminal from ssh when called from one).

### Upgrade from v0.1.0
1. `git pull` in the stack directory.
2. `docker compose build` – both images (the build context is now the repository root; the sandbox image adds `sshpass`).
3. `docker compose up -d` – recreates both containers (also needed for the new log limits); recreating `tentaclai`
   ends running sessions and Remote Control.
4. Optional, if you commit to the repository: `git config core.hooksPath .githooks`.

No `.env` or configuration changes. **Changed:** `./ssh-host.sh` now runs inside tentacontrol (both containers must be
running) and takes `--jump <alias>` / `--sudo` / `--sudo-cmd`; the hostkey, sudo and test commands are new.

## v0.1.0 – 2026-10-18

First public release.

### Highlights
- Sandbox container with Claude Code, permanent Remote Control session, persistent tmux sessions.
- Services as files (`api`, `mcp`, `git`, `docker`, `db`, `web`, `files`), `svc` gateway enforcing `ro`/`rw`.
- Systems, tentacontrol web admin with 50 templates, onboarding (`/onboard`) and system inventory (`/inventory`), topology view.

### Upgrade
First release – fresh install, see [Getting started](README.md#getting-started).
