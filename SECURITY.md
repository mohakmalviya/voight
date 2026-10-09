# Security policy

Voight is a pre-audit prototype. Do not use it as the only protection for sensitive data.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue, and do not post exploit details, credentials, invitation codes, database files or logs publicly.

Include the affected commit, your deployment topology (mode, proxies, `TRUSTED_PROXIES`), a reproduction against a local demo, and the expected and actual behaviour.

Only test against your own deployments. Never test against third-party sites without their permission.

## Scope

In scope: bypassing budgets, blocks, clearances or private-mode admission; header or identity spoofing; anything that lets the origin be reached without passing the gateway's checks; leaks of addresses, URLs or secrets into storage or logs.

Ways past the human check go here too, never in a public issue or pull request. The basic rules in this repository only catch automation that announces itself, so getting past them alone is expected.

Out of scope: limitations already documented in [docs/threat-model.md](docs/threat-model.md), such as slow in-budget agents, distributed IP pools and volumetric floods. New techniques that make those cheaper are still welcome as reports.
