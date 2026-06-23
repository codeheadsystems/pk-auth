# Security Policy

pk-auth is an authentication library, so security reports are taken seriously
and handled with priority. Thank you for helping keep it and its users safe.

## Supported versions

Fixes land on the latest published `1.x` line. Maven Central and npm releases
are immutable, so a security fix ships as a new patch (or minor) release rather
than a re-publish of an affected version — upgrade to the latest release to pick
it up.

| Version            | Supported          |
| ------------------ | ------------------ |
| Latest `1.x` release | :white_check_mark: |
| Older `1.x` releases | Fix only via the next release |
| `0.x` (pre-stable) | :x:                |

The browser SDK (`@pk-auth/passkeys-browser`) shares the same version line as
the JVM artifacts and follows the same support window.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a
suspected vulnerability.** Public disclosure before a fix is available puts
downstream users at risk.

Use one of these private channels instead:

1. **GitHub private vulnerability reporting (preferred).** On the repository,
   go to the **Security** tab → **Report a vulnerability**, or open
   <https://github.com/codeheadsystems/pk-auth/security/advisories/new>. This
   creates a private advisory thread visible only to you and the maintainers.
2. **Email.** Send details to **ned.wolpert@gmail.com** with `pk-auth security`
   in the subject line.

Please include, as far as you can:

- The affected module(s) and version (e.g. `pk-auth-core 2.1.0`).
- A description of the issue and its impact (what an attacker can do).
- Steps to reproduce — a minimal proof of concept, failing test, or request
  sequence is ideal.
- Any relevant configuration (adapter, persistence backend, SPI implementations).

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment (severity, affected versions, whether it reproduces)
  within **10 business days**.
- We aim to ship a fix within **90 days** of triage and will keep you updated on
  progress. Complex issues may take longer; we will say so.
- We follow **coordinated disclosure**: we ask that you keep the report private
  until a fix is released and a GitHub Security Advisory is published. We are
  happy to credit you in the advisory unless you prefer to remain anonymous.

## Scope

This policy covers the pk-auth library, its three host adapters
(`pk-auth-spring-boot-starter`, `pk-auth-dropwizard`, `pk-auth-micronaut`), the
wire contract, and the browser SDK in this repository.

It does **not** cover the responsibilities a host application retains — TLS,
network ingress, secrets management, and the authorization layer above
authentication. See [`docs/threat-model.md`](docs/threat-model.md) for the
trust boundaries and STRIDE analysis, and [`docs/stability.md`](docs/stability.md)
for the SPI versioning and stability guarantees.

> **Maturity note.** As stated in the repository README, this project's code is
> AI-generated and has not undergone a formal third-party security review unless
> a note in the repository says otherwise. Evaluate it accordingly before
> production use.
