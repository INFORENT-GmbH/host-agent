# Security policy

The agent runs with elevated privileges on servers, so we treat security
reports with priority.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them
privately through GitHub's
[private vulnerability reporting](https://github.com/INFORENT-GmbH/host-agent/security/advisories/new)
("Security" tab → "Report a vulnerability").

Please include the agent version (`<brand>-agent version`), the platform, and
steps to reproduce. We acknowledge reports within three working days and keep
you informed until a fix is released. Fixed versions reach enrolled hosts
through the regular self-update channel.

## Supported versions

Only the latest released version receives fixes. Hosts on the `stable` or
`testing` update channel pick it up automatically.

## Scope

In scope: this agent, its packaging and install scripts, and the wire protocol
as implemented here. The design goals the agent must uphold are listed under
[Security model](README.md#security-model) — a way to make the agent execute
something the portal did not release, to read the host token as an
unprivileged user, or to smuggle code into local checks is exactly what we
want to hear about.
