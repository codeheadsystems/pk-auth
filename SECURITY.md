# Security Policy

pk-auth is an authentication library, so security reports are handled with priority.

## Supported versions

Fixes land on the latest published `1.x` line. Maven Central and npm releases are immutable, so a
security fix ships as a new patch (or minor) release rather than a re-publish of an affected
version. Upgrading to the latest release picks up the fix.

| Version              | Supported                     |
| -------------------- | ----------------------------- |
| Latest `1.x` release | :white_check_mark:            |
| Older `1.x` releases | Fix only via the next release |
| `0.x` (pre-stable)   | :x:                           |

The browser SDK (`@pk-auth/passkeys-browser`) shares the same version line as the JVM artifacts and
follows the same support window.

## Reporting a vulnerability

Suspected vulnerabilities are not reported through public issues, pull requests, or discussions.
Public disclosure before a fix is available puts downstream users at risk.

Two private channels accept reports:

1. GitHub private vulnerability reporting (preferred). On the repository, the Security tab offers
   Report a vulnerability, and
   <https://github.com/codeheadsystems/pk-auth/security/advisories/new> opens the same form. The
   report creates a private advisory thread visible only to the reporter and the maintainers.
2. Email to ned.wolpert@gmail.com with `pk-auth security` in the subject line.

A report includes, as far as possible:

- The affected module or modules and the version (for example `pk-auth-core 2.1.0`).
- A description of the issue and its impact (what an attacker can do).
- Steps to reproduce, ideally a minimal proof of concept, failing test, or request sequence.
- Any relevant configuration (adapter, persistence backend, SPI implementations).

## Response timeline

- Acknowledgement within 3 business days.
- An initial assessment (severity, affected versions, whether it reproduces) within 10 business
  days.
- A fix within 90 days of triage, as the target, with progress updates to the reporter. Complex
  issues may take longer, and the maintainers say so.
- Coordinated disclosure. The report stays private until a fix is released and a GitHub Security
  Advisory is published. The reporter is credited in the advisory unless they prefer to remain
  anonymous.

## Scope

This policy covers the pk-auth library, its three host adapters (`pk-auth-spring-boot-starter`,
`pk-auth-dropwizard`, `pk-auth-micronaut`), the wire contract, and the browser SDK in this
repository.

It does not cover the responsibilities a host application retains: TLS, network ingress, secrets
management, and the authorisation layer above authentication. See
[`docs/threat-model.md`](docs/threat-model.md) for the trust boundaries and STRIDE analysis, and
[`docs/stability.md`](docs/stability.md) for the SPI versioning and stability guarantees.

## Maturity

The project's code is AI-generated and has not undergone a formal third-party security review
unless a note in the repository says otherwise, as stated in the repository README. A production
deployment should be evaluated against that status.
