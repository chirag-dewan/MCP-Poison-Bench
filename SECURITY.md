# Security & responsible use

MCP-Poison-Bench is a **defensive-security research benchmark**. It contains controlled,
**defanged** tool-poisoning fixtures (a local no-op sink tool and a synthetic token) used
to measure how models acting as MCP clients handle untrusted server metadata, and to
evaluate a client-side defense.

## Acceptable use

- Use the poisoned servers and payloads **only against models/clients you own or are
  explicitly authorized to test**, in a local or otherwise authorized environment.
- **Do not** point these fixtures at third-party deployed MCP hosts or production servers
  without coordinated disclosure and authorization.
- The injection techniques here are the publicly-documented MCP tool-poisoning classes;
  nothing in this repo is a working exploit against a real service.

## Reporting a vulnerability

If you find a security issue **in this repository** (e.g. an accidentally-committed
secret, or a fixture that is not actually defanged), please open a GitHub issue for
non-sensitive reports, or contact the maintainer privately via the contact on
[cdewan.me](https://cdewan.me) for anything sensitive. Please do not include working
exploit payloads in public issues.

If your finding concerns a **third-party MCP client, host, or model** that you discovered
using this harness, follow that project's coordinated-disclosure process and the
responsible-disclosure norms for adversarial ML research before public release.
