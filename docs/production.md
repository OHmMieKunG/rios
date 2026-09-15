# Production deployment profile

RIOS is deployable as a single-process, single-node educational network
simulation service. This profile covers the implemented protocols and local
management frontends. It does not claim carrier-grade protocol conformance,
multi-tenant isolation, high availability, or safe exposure of Telnet.

## Build and verification

The repository pins Rust 1.98.1 and commits `Cargo.lock`. Build the release
binary only after these gates pass:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release --locked
```

The release profile enables thin LTO, one code-generation unit, symbol
stripping, and abort-on-panic. CI repeats the gates and checks dependencies
against the RustSec advisory database.

## Secure SSH startup

SSH refuses to start without a stable host-key path and at least one explicit
authentication method:

```sh
install -d -m 0700 /var/lib/rios
RIOS_SSH_HOST_KEY=/var/lib/rios/ssh_host_ed25519 \
RIOS_SSH_AUTHORIZED_KEYS=/etc/rios/authorized_keys \
RIOS_SSH_PASSWORD= \
RIOS_STATE_FILE=/var/lib/rios/lab-state.json \
RIOS_LOG_FORMAT=json \
RUST_LOG=info \
target/release/rios ssh /etc/rios/topology.yaml 2001
```

RIOS generates a missing Ed25519 host key with mode `0600` on Unix. Authorized
key options are rejected because their restrictions are not implemented. A
password may be supplied instead, but key-only authentication is preferred.
Listeners bind to loopback; use an authenticated tunnel or host-level forwarding
when remote access is needed.

## State and recovery

`write memory` saves all device startup configurations in one versioned JSON
file. The default is `<topology>.rios-state.json`; `RIOS_STATE_FILE` selects a
writable service-owned path. Writes are atomic and synchronized. Startup rejects
malformed, oversized, or unsupported-version state before applying it.

Back up the state file after configuration changes. To roll back, stop RIOS,
replace it with a known-good copy, and restart. To return to the topology's base
configuration, move the state file aside and restart. Runtime ARP, MAC, OSPF,
DHCP lease, NAT, event-queue, and packet state intentionally do not persist.

## Resource and lifecycle controls

- `RIOS_MAX_SESSIONS` defaults to 128 across all device listeners.
- `RIOS_IDLE_TIMEOUT_SECS` defaults to 900.
- Remote command lines and SSH exec commands are limited to 4096 bytes.
- Saved state is limited to 16 MiB.
- SIGINT and SIGTERM stop listeners; SSH disconnects clients and Telnet sends a
  shutdown notice before closing.
- `RIOS_LOG_FORMAT=json` emits structured logs to stderr; `RUST_LOG` controls
  filtering.

Run the process under a service manager with restart-on-failure, file-descriptor
limits, a dedicated unprivileged account, and writable access only to its state
and host-key paths. Do not expose the unauthenticated Telnet listeners outside
the local host.

## Remaining production boundaries

The simulator remains one failure domain and serializes lab mutations. There is
no live state replication, online backup coordination, per-user authorization,
configuration encryption, metrics endpoint, or distributed control plane.
Packet and CLI parsers have deterministic tests but not yet continuous fuzzing.
Add those capabilities before multi-tenant or Internet-facing deployment.
