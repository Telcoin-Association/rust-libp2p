# Security review of rust-libp2p fork

## Problem

We run a Telcoin-Association fork of rust-libp2p as our networking stack. The upstream codebase has not had a published third-party security audit. Since we depend on gossipsub for consensus message dissemination, Kademlia for peer discovery, and the relay protocol for NAT traversal, bugs in these subsystems can directly affect network liveness and integrity.

A full-repo review covering all ~68 workspace crates turned up 25 findings (19 confirmed or partially valid, 6 design decisions). No critical vulnerabilities were found, but several confirmed logic bugs and resource-management issues are worth addressing before we cut a production release. The most notable is an inverted score comparison in gossipsub's heartbeat that makes fanout replenishment select the wrong peers (or no peers at all when scoring is disabled).

## Solution

Add the full findings report (`report.md`) to the repo so maintainers and upstream contributors can review it alongside the code. The report covers three review passes:

1. Structured pattern-matching review of every crate, covering unsafe code, crypto, error handling, concurrency, and input validation. Each finding was independently verified by a second reviewer tracing the actual source.
2. A second pass that attempted to falsify every finding from pass 1, tightening wording and downgrading or confirming severities.
3. A Nemesis audit (Feynman first-principles interrogation and state inconsistency analysis) on gossipsub, Kademlia, and relay+swarm. This pass found 6 new logic bugs the pattern-matching approach missed entirely, including the gossipsub fanout inversion and two off-by-one errors in the relay's per-peer limits.

Each finding includes the exact file and line, a trigger sequence, impact assessment, and a proposed fix. Design decisions and false positives are documented with explanations so they don't get re-raised.

The confirmed bugs should be evaluated for upstream PRs to `libp2p/rust-libp2p`. The medium-severity findings (gossipsub fanout, websocket 256 MiB default, webrtc-websys channel drop, kad unfiltered default, server metrics bind, floodsub auth) warrant attention before production deployment.
