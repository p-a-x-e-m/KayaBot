# Security Policy

## Supported versions

This project is maintained on a best-effort basis. Only the latest commit on the
default branch receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest `origin` branch | ✅ |
| older commits | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately using GitHub's
[private vulnerability reporting](https://github.com/p-a-x-e-m/KayaBot/security/advisories/new)
form, which is enabled for this repository.

Please include:

- a description of the issue and its impact,
- the file and line (or a minimal reproduction),
- the version/commit you tested,
- any suggested fix if you have one.

You can expect an acknowledgement within a few days. Please allow reasonable time
for a fix to be released before any public disclosure.

## Scope

This is a personal automation script. The most relevant risks are:

- **Credential handling** — account credentials are read from the environment and
  must never be committed. The cookie store is encrypted at rest (see below).
- **Automated form submission** — the bot submits proposals on your behalf using
  your account; anything that could be manipulated into submitting unexpected
  proposals is in scope.
- **Browser automation** — the Chrome driver intentionally runs with Chrome's
  default security posture. Anything that would require disabling browser
  protections to work is out of scope.

## Security design notes

- Credentials are read only from `KAYA_USERNAME` / `KAYA_PASSWORD`; there are no
  hardcoded fallbacks.
- Session cookies are encrypted at rest in `kaya.db` using Fernet, with the key
  supplied via `KAYA_COOKIE_KEY`.
- `kaya.db`, logs and screenshots are gitignored and must never be committed —
  they can contain live session material.
- Debug screenshots of authenticated pages are off unless `KAYA_DEBUG_ARTIFACTS`
  is explicitly set, because they can capture account details.

## Automated protections

This repository has GitHub secret scanning, push protection and Dependabot
alerts/security updates enabled.

## Out of scope

- Use of the bot against a target you are not authorised to automate.
- Violations of the target site's terms of service.
