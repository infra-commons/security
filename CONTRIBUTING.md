# Contributing

infra-commons hosts **generic, reusable infrastructure** — CI/CD workflows, deploy and
security templates, and automation runtime — shared as open source across multiple
independent projects.

## Golden rule: nothing business-specific lands here

These repositories are **public**. Keep them generic. Do **not** commit — in code,
comments, commit messages, or PR titles/bodies — any of:

- personal names or contact details
- private repository names, client names, or other brand-specific identifiers
- host paths, usernames, or machine names (use `$HOME`, placeholders, env vars)
- specifics of operational incidents or outages (describe the class of problem, not the event)
- secrets or credentials of any kind

Caller repositories supply their own configuration and secrets at use time, so nothing
deployment-specific needs to live here. When in doubt, generalise.

Commits to these repositories use a neutral project identity
(`infra-commons maintainer <noreply@infra-commons>`), not a personal one.

## Licence

This project is licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE).
By contributing, you agree that your contributions are licensed under the same terms.
