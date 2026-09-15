# Phase 9 implementation report

Phase 9 adds an SSH frontend without creating a second CLI implementation.

Implemented:

- `rios ssh <topology.yaml> [base-port]` starts one loopback-only SSH listener
  per device in stable topology-name order.
- Password authentication using `RIOS_SSH_USERNAME` and `RIOS_SSH_PASSWORD`.
  The username defaults to `admin`; the password has no default.
- Public-key authentication from `RIOS_SSH_AUTHORIZED_KEYS`, using the OpenSSH
  authorized-keys parser and exact key-data matching. Unsupported per-key
  options fail startup rather than silently losing their restrictions.
- Persistent host-key loading or generation through `RIOS_SSH_HOST_KEY`, with
  Unix mode `0600` for generated keys. Existing encrypted keys can use
  `RIOS_SSH_HOST_KEY_PASSWORD`.
- Ed25519 SSH host keys and encrypted transport through `russh` with its ring
  cryptography backend.
- An independent `CliSession` for each SSH channel and one shared virtual lab.
- A frontend-neutral device-line function shared by terminal, scripted stdin,
  and SSH paths. Parsing, execution, ping requests, errors, prompts, hostname
  changes, and packet traces therefore have one implementation.
- Interactive PTY input with echo, backspace, contextual `?` help, Ctrl+C input
  cancellation, Ctrl+Z configuration exit, CR/LF handling, and clean `exit`.
- SSH exec channels for one non-interactive User EXEC command. Successful
  commands return process status 0; parser, executor, and simulation failures
  preserve their CLI diagnostics and return status 1.
- One loopback-only Telnet listener per device through
  `rios telnet <topology.yaml> [base-port]`, defaulting to ports 3001 onward.
- Streaming Telnet IAC, option, and subnegotiation decoding plus echo and
  suppress-go-ahead negotiation. Telnet and SSH use the same remote terminal
  adapter and device-session executor.
- No OS thread per device and no OS network interface for simulated packets;
  TCP is used only by the optional SSH frontend.

Validation:

- An in-process encrypted SSH integration test authenticates, allocates a PTY,
  enters privileged EXEC mode, executes `show ip interface brief` against real
  device state, closes the channel, and establishes a second connection using
  an authorized public key.
- The same encrypted test executes valid and invalid non-interactive commands,
  checking their output and exit statuses.
- A TCP integration test enters privileged mode and reads real interface state
  through the Telnet frontend. A decoder test covers fragmented Telnet
  subnegotiation.
- Host-key tests prove generation, private Unix permissions, stable reload, and
  authorized-keys parsing and option rejection.
- A manual OpenSSH session against the two-router example produced the banner,
  mode-changing prompt, interface table, and clean connection closure.
- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS.

Known limits: authorized keys load once at startup and key options are not implemented. Exec
channels run one command from a fresh User EXEC session; they do not retain mode
between invocations. Remote sessions do not yet support arrow-key history or tab
completion. One async mutex serializes commands across SSH clients. This keeps
mutation deterministic; a lab actor queue is the next step only if remote
command contention becomes relevant. Telnet is intentionally unauthenticated
and loopback-only; it must not be treated as a secure management transport. The
web/GUI frontend remains deferred.

Production hardening now adds atomic versioned startup-state persistence,
validated resource limits, idle timeouts, secure SSH defaults, structured JSON
logging, and graceful SIGINT/SIGTERM shutdown. See `docs/production.md`.
