# security-review-findings

## Overview

Adds a comprehensive security review report covering all ~68 crates in the rust-libp2p workspace. Three review passes were conducted, producing 25 findings (7 medium, 12 low, 6 informational) and 1 false positive.

## Changes

### Security review report (`report.md`)

- Full findings from three review passes: pattern-matching, re-verification, and Nemesis (Feynman + state inconsistency) audit
- 26 findings total, each with file:line references, trigger sequences, and proposed fixes
- 10 coupled state pairs verified as correctly synchronized across gossipsub, relay, and swarm
- Cross-cutting observations on unsafe code (zero in production), dependency trust chain, resource exhaustion defenses, and CI posture

### Confirmed logic bugs (from Nemesis pass)

- Gossipsub heartbeat fanout replenishment uses `< publish_threshold` instead of `>= publish_threshold` at `behaviour.rs:2476`, inverting peer selection. With scoring disabled (default), fanout replenishment is a permanent no-op.
- Relay per-peer reservation limit uses `>` instead of `>=` at `behaviour.rs:408`, allowing `max + 1` reservations per peer. Same pattern for circuits at line 535.
- Relay `ReservationReqAcceptFailed` handler at `behaviour.rs:475-483` does not clean up the optimistically-inserted reservation entry, creating phantom reservations until the connection closes.
- Relay IP rate limiter defaults to allow (`unwrap_or(true)`) when `multiaddr_to_ip` returns `None` at `rate_limiter.rs:50`.
- Gossipsub RPC handler processes subscriptions from blacklisted peers before checking graylist at `behaviour.rs:3267-3278`.

### Confirmed resource/config issues

- WebSocket `MAX_DATA_SIZE` defaults to 256 MiB at `framed.rs:49`, allowing large single-message allocations from peers.
- WebRTC-WebSys `mpsc::channel(4)` drops inbound `RtcDataChannel` handles when full at `connection.rs:55-59`.
- Server metrics endpoint binds `0.0.0.0:8888` with no auth at `http_service.rs:36`. Comment incorrectly says "localhost."
- Kad `StoreInserts::Unfiltered` default stores inbound records without application validation.
- Floodsub wire format has no signature field; `from` is self-asserted.

### Low-severity and informational items

- QUIC `Config::new` panics via unwrap on TLS construction failure (local-only, not network-triggered)
- Secp256k1 DER parsing has an open TODO for stricter RFC 5915 conformance
- ECDSA/secp256k1 keygen uses `thread_rng()` while ed25519 uses `OsRng` (both are CSPRNGs, inconsistency only)
- Memory transport `debug_assert!` stripped in release builds
- TLS `extract_single_certificate` panics on invariant violation (not remotely triggerable)
- Memory connection limits can use stale stats when `memory_stats()` returns None
- `deny.toml` ignores RUSTSEC-2024-0436 (unmaintained `paste`) without a comment
- Several spec-aligned design decisions documented (pnet no-MAC, mplex contention, yamux 256-stream cap, plaintext in `full`, identify unsigned addresses)

### False positive documented

- Swarm `pending_swarm_events` VecDeque: initially flagged as unbounded, but the polling discipline in `poll_next_event` makes it effectively a single-item buffer. Documented so it doesn't get re-raised.
