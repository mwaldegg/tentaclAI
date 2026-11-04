# Contributing

Thanks for your interest in tentaclAI! Issues, ideas and pull requests are welcome.

## Ground rules

- **Never commit site data.** `.env`, `services/*.json`, `systems/*.json`, `ssh/`, `local/CLAUDE.md`, `compose.override.yaml`
  and `data/` are git-ignored on purpose. Check `git status` before every commit – no tokens, hostnames or IPs of your setup.
- **Keep it generic.** Code, templates and docs must work for any installation; site specifics belong in the files above.
- **English** for code, UI, messages, docs and templates.
- **One implementation.** Parsing of `.env`, services, systems and SSH hosts lives in `lib/tclib.py` – extend it instead of
  writing another parser.
- **Guard rails first.** Changes to `svc` must keep `read`/`write` enforcement and never put secrets into command lines, logs or the UI.

## Development

- Enable the pre-commit check once per clone: `git config core.hooksPath .githooks` – it refuses site files and
  anything that looks like a token or private key (`scripts/check-site-data.sh`). CI runs the same check on every push.

- Tests come in three stages (details in `CLAUDE.md`):
  1. `scripts/test-quick.sh` after every change – no Docker, a few seconds: syntax, ShellCheck, site-data check, pytest
     unit tests and every tentacontrol page rendered with dummy data. CI runs it on every push.
  2. `REUSE=1 ONLY=<sections> scripts/test-sandbox.sh` for changes to security boundaries, the gateway or the entrypoint –
     end-to-end in a scratch copy with its own compose project (`tctest`), never touching your running stack.
  3. The full `scripts/test-sandbox.sh` before every release (CI runs it on every push, too).
  For manual experiments use the same isolation (own project, container names, port, scratch `data/`) – recreating the
  real `tentaclai` container ends running sessions and Remote Control.
- Releases: `scripts/release.sh X.Y.Z "subtitle"` – checks, both test stages, CI, then changelog, tag and GitHub release.
- UI: tentacontrol is FastAPI + Jinja + HTMX; static assets are vendored in the image, no CDNs at runtime.

## Service templates

New templates go to `services/_templates/<name>.json` with a `_meta` block (`title`, `category`, `setup`), `${VAR}`
placeholders for secrets with a descriptive name (`GRAFANA_TOKEN`; a second service from the same template gets its own
`<NAME>_…` variables automatically), a `test_path` that needs the token, and `{{DOMAIN}}` where the site's domain belongs
(filled with the placeholder `example.com` – the user enters the real address).

## Pull requests

Small, focused PRs with a short description of *what* and *why*. PRs are squash-merged.

- **Changelog:** nothing to do. Don't edit `CHANGELOG.md` (two PRs editing it always collide). If you like, put one
  line into the PR description – it goes into the changelog as written:

  ```
  Changelog: **SSH → Add host: "This host" works again** – the button did nothing in the browser.
  Upgrade: `docker compose build control`, `docker compose up -d control`   (only if an installation needs a step)
  ```

  Without it we write the entry when the PR is merged.
- **A test** that fails without your change and passes with it. A bot comment on the PR tells you when it's missing.

### Tests

Run `scripts/test-quick.sh` (no Docker, under a minute; a single test: `scripts/test-quick.sh -k <name>`). Put the
test next to the closest existing one:

| You changed | Test goes to | Typical check |
|---|---|---|
| a page or template (`control/app/templates/`, `routes/`) | `tests/test_pages.py` | `client.get("/page").text` contains the right HTML |
| `svc` (`build/svclib/`) | `tests/test_svc.py` | call `svc.<function>` with `monkeypatch`ed helpers |
| `lib/tclib.py` | `tests/test_tclib.py` | plain function calls |
| other tentacontrol code (`control/app/*.py`) | the `tests/test_<module>.py` of that module | |

Example – a template fix (the alias quotes in the *This host* button, #99):

```python
page = client.get("/ssh/new").text
assert "f.alias.value=&#34;" in page   # escaped, so the onclick attribute doesn't end early
```

Security boundaries (svc access modes, the gateway, the entrypoint) also get an end-to-end check in
`scripts/test-sandbox.sh` – see stage 2 above; if you can't run Docker, say so in the PR and we run it.
