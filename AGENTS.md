# AgenSysAdmin development and operations

This repository contains reusable code, synthetic tests and anonymized examples.
Real inventories, credentials, keys, logs, server baselines and browser captures
belong in an external private workspace. Never publish them or copy them into
fixtures. Keep the original operational workspace separate when consolidating.

Preserve existing user changes and use small, reviewable changes. Run focused
tests and the complete regression suite for code changes. Use structured tool
implementations under `src/agensysadmin/tools`; preserve truthful UNKNOWN and
partial-audit results. A security score is not a certification.

Use verified host-key fingerprints or explicit known-hosts stores. Never add an
automatic-trust escape hatch or pass passwords as tool arguments/command text.
Keep the MCP interface diagnostic-only by default. Server enrollment and policy
changes belong to operator-owned local configuration, not model-supplied flags.

Read-only source inspection and tests with synthetic data are allowed. Live
server operations are a separate task: inspect before changing, explain the
concrete plan, obtain explicit approval for production/business-critical writes
and dangerous operations, verify after the change, and keep private operational
notes in the private workspace. Do not contact real servers merely to run tests.

Use metadata-only journals. Do not expand logging to raw shell commands, stdout,
stderr, file contents, credentials or provider addresses. Keep sudo credentials
and configuration stdin separated and preserve exact file-write semantics.
