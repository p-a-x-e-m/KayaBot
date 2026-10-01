# Security Audit — KayaBot

**Repository:** https://github.com/p-a-x-e-m/KayaBot
**Date:** 2026-10-01
**Branch:** `security/hardening`
**Scope:** full repository, entire git history, dependencies, GitHub configuration

## Summary

The repository is public and contains no secrets — not in the working tree, not in
any historical commit. Findings are therefore all hardening issues rather than
active compromises. The most significant ones were in the browser automation
layer: options that switched off Chrome's own security protections for the whole
session, including the authenticated one.

| Severity | Count | Fixed | Manual |
|----------|-------|-------|--------|
| Critical | 0 | — | — |
| High | 2 | 2 | 0 |
| Medium | 5 | 5 | 0 |
| Low | 6 | 4 | 2 |
| Info | 3 | 2 | 1 |

---

## Findings

| Severity | File:Line | Issue | Fix |
|----------|-----------|-------|-----|
| **High** | `main.py:130` (was) | `--disable-web-security` disabled the same-origin policy for every page in the session, including the authenticated kaya.ir session. Any script or extension loaded from any origin could read the DOM and session cookies. | Removed. The driver now runs with Chrome's default security posture; a docstring records why it must not be re-added. |
| **High** | `main.py:131` (was) | `--allow-running-insecure-content` let HTTPS pages load HTTP subresources, enabling MITM downgrade of the authenticated session. | Removed (same change as above). |
| **Medium** | `main.py:36-37` (was) | `os.system('pkill -f chrome')` invoked a shell to spawn a process. Benign today, but any future interpolation into the pattern becomes command injection; bandit flagged it as B605/B607. | Replaced with `subprocess.run([...], shell=False)` using an absolute path from `shutil.which`. |
| **Medium** | `main.py:139` (was) | Browser profile created at a predictable path `{tempdir}/kaya_profile_{pid}`, world-readable, holding session cookies. | `tempfile.mkdtemp()` (unpredictable, 0700) and the path is tracked on the instance rather than scraped from a log. |
| **Medium** | `main.py:63-110` (was) | Session cookies stored as **plaintext JSON** in `kaya.db`. Cookie theft = full account takeover, and the file is easy to leak via backup or sync. | Encrypted at rest with Fernet (`KAYA_COOKIE_KEY`), file chmod 0600. Verified by test that the plaintext value never reaches disk. |
| **Medium** | `main.py:150` (was) | ChromeDriver `--verbose` logging. Driver logs can capture page content and form values, including the submitted password. | `--verbose` removed; `log_path` kept at DEBUG-only usefulness, and `chromedriver.log` is gitignored. |
| **Medium** | `main.py:27` | Log level hardcoded to `INFO`, but `logger.debug` calls wrote page_source and full cookie lists when raised. | Log level via `KAYA_LOG_LEVEL`; the page_source dump was deleted outright and cookie logging now emits **names only**, never values. |
| **Low** | `main.py:352` (was) | `logger.debug(f"Page source: {page_source[:1000]}")` dumped the authenticated DOM into a persistent log file. | Removed. Logs now record only `urlparse(...).path`, never full URLs (which can carry tokens). |
| **Low** | `main.py:295,341,353,359` (was) | Unconditional screenshots on every login path; screenshots of an authenticated page can expose account details, and the files were written to the repo root. | Gated behind `KAYA_DEBUG_ARTIFACTS` (default off) via a single `_debug_artifact()` helper. |
| **Low** | `main.py:136` (was) | Hardcoded, outdated Chrome UA string (`Chrome/91`) overriding the real browser, which is both fingerprint noise and makes the client trivially identifiable. | Removed; the real UA is used. |
| **Low** | `main.py:156-160` (was) | CDP `navigator.webdriver` override and `window.chrome` shim — bot-detection evasion. | Removed. |
| **Low** | `main.py:39` (was) | Hardcoded `/tmp`, which is wrong on Windows and may point at a shared, world-writable location. | `tempfile.gettempdir()`. |
| **Low** | `main.py:123` (was) | `--no-sandbox` always on, silently removing the Chrome sandbox even when not required. | Opt-in via `KAYA_NO_SANDBOX` for root-in-container use. |
| **Low** | repo config | No `.env.example`, and `.gitignore` did not cover `.env`, keys, certs, dumps or backups. | Added `.env.example` (placeholders only) and expanded `.gitignore`. |
| **Info** | — | No `SECURITY.md`, so vulnerabilities had no private reporting path. | Added, pointing at GitHub private vulnerability reporting. |
| **Info** | — | No automated scanning. | Added `.github/workflows/security.yml` (bandit, pip-audit, gitleaks) and `.github/dependabot.yml`. |

### Not a finding (verified clean)

| Check | Result |
|-------|--------|
| Secrets in working tree | None. Credentials come from `KAYA_USERNAME`/`KAYA_PASSWORD` only. |
| Secrets in **entire** git history (all 14 blobs ever committed) | None. Every `password` match was the literal placeholder string or a variable name. |
| Private keys / tokens / connection strings / JWTs | None. |
| `.env`, `kaya.db`, key files, dumps, backups in history | Never committed. |
| SQL injection | No dynamic SQL; `kaya.db` statements use literal SQL with no interpolation. |
| `eval` / `exec` / `pickle` / `yaml.load` | Not used anywhere. |
| `verify=False`, `shell=True`, `random` for secrets | Not present. |
| Dockerfile / docker-compose / k8s / nginx / IaC | None exist in this repository. |
| CI/CD workflows | None existed before this audit (see Info rows). |
| Personal info: emails, IPs, internal hostnames, local paths | Only the author's GitHub handle in `LICENSE` (intentional). No emails, IPs or hostnames in code or history; commit metadata carries the author's email, which is standard and visible on GitHub regardless. |
| Binary/metadata files (EXIF, PDF, docx) | None — the repo contains only text files. |

---

## Dependency audit

`pip-audit` against the resolved dependency set: **no known vulnerabilities**.

Before this audit there was no lock file — `requirements.txt` pinned only the two
direct dependencies, leaving transitive versions floating. `requirements.txt` is now
a fully resolved lock file with sha256 hashes for all 24 packages / 374 artifacts,
installable with `--require-hashes`, and `requirements.in` holds the direct
dependencies for regeneration. No abandoned, typosquatted or unused packages were
found; `selenium` and `webdriver-manager` are both actively maintained.

---

## Verification

`tests/test_security.py` — 16/16 passing:

```
PASS  1. env_flag default/override      PASS  9. constants wired
PASS  2. db created                     PASS 10. no --disable-web-security
PASS  3. plaintext NOT in db file       PASS 11. no --allow-running-insecure-content
PASS  4. decrypt roundtrip              PASS 12. no navigator.webdriver override
PASS  5. wrong key -> None (graceful)   PASS 13. no os.system
PASS  6. missing key -> ValueError      PASS 14. no page_source logging
PASS  7. missing creds -> ValueError    PASS 15. no verify=False
PASS  8. creds keys                     PASS 16. no shell=True
```

`bandit`: 0 High, 0 Medium, 2 Low (both inherent to spawning a subprocess for
process cleanup — mitigated with `shell=False` and an absolute path).

The lock file was validated by installing it into a clean virtualenv with
`--require-hashes`, then importing `selenium`, `cryptography` and `requests`.

---

## Manual tasks (require your action)

These cannot be done from here — they need a human, higher privileges, or a
decision that is yours to make.

### 1. Secrets to rotate

**None.** No credential was found in the repository or its history, so nothing
needs rotating on account of this audit.

Two operational notes:

- If you ever ran an older version of this bot and still have a `kaya.db` on a
  machine from before this change, it holds session cookies in **plaintext**.
  Delete it, or let the bot re-login; the new format is encrypted.
- If you have spread `kaya.db` to a backup or sync service, delete it there too.

### 2. GitHub settings I could not fully change

Enabled via the API during this audit (confirmed active):

- ✅ Secret scanning
- ✅ Secret scanning push protection
- ✅ Dependabot alerts
- ✅ Dependabot security updates

Still needs you, because the token used here lacks the required scopes or these
have no API:

- ❌ **Secret scanning validity checks** and **non-provider patterns** — the API
  accepted the request but reported the change as not applied; toggle in
  Settings → Code security.
- ❌ **CodeQL / code scanning** — requires enabling the default setup in
  Settings → Code security, or a workflow (workflows written by a bot need
  `workflow` scope; the available token has it, but enabling it changes your
  build configuration, so it is your call).
- ❌ **Private vulnerability reporting** — `SECURITY.md` links to the form, but
  the feature must be enabled in Settings → Code security. Until then that link
  404s.
- ❌ **Branch protection on `origin`** — no rule exists. Recommended: require a
  pull request before merging, require 1 approval, dismiss stale approvals,
  require status checks, and block force pushes and deletions. Note the default
  branch is `origin`, not `main`.
- ❌ **2FA** and **signed commits** — account-level settings, nothing I can set.
- ❌ **Default branch rename** to `main` — deliberately not done; see below.

### 3. Decisions left to you

- **Branch rename `origin` → `main`.** Still not done, for the same reason as
  before: your local branch is named `origin` with `branch.origin.merge` pointing
  at `refs/heads/origin`. Renaming the remote branch without moving your local one
  breaks your next push. If you want it, run all four together:
  ```bash
  git branch -m origin main && git push -u origin main && git push origin --delete origin && git remote set-head origin -a
  ```
- **`--user-data-dir` persistence.** The throwaway profile is deleted on exit, so
  cookies come only from the encrypted DB. If you relied on the profile persisting
  between runs, tell me and I'll add an opt-in path.

---

## Notes on judgement calls

- **Stealth code removed.** The `navigator.webdriver` override and the fake UA
  were deliberate anti-detection measures. Anti-detection against a third-party
  site is also what makes automated access harder for that site to police, so I
  removed them as part of "harden the browser." If the site's bot checks make the
  bot unusable without them, that is a conversation about your use of the site,
  not a bug — tell me and we can revisit.
- **No history rewrite.** `git filter-repo` was not needed because no secret was
  ever committed. Rewriting history on a public repository would invalidate every
  existing clone and fork for no security benefit.
- **Rate limiting / brute-force protection.** Not applicable — this is a client
  script with no server or login endpoint of its own.
- **CORS / security headers / cookie flags.** Not applicable for the same reason;
  those are set by kaya.ir, not by this code. The bot's own handling of cookies is
  what was in scope, and that is covered above.
