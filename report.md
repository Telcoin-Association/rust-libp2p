# Code Review: rust-libp2p Full Repository
Date: 2026-04-03 (Updated 2026-04-04 — Nemesis Pass)
Scope: All crates in the rust-libp2p workspace (~68 crates including core, identity, transports, protocols, swarm, muxers, and misc utilities)

## Summary
Comprehensive security review of the rust-libp2p networking stack covering all ~68 workspace crates. Three review passes were conducted: (1) structured code-review-security skill with parallel subagent verification, (2) second-pass re-verification attempting to falsify findings, and (3) Nemesis audit applying Feynman first-principles interrogation and State Inconsistency analysis to the three most complex subsystems (gossipsub, Kademlia, relay+swarm pool).

The codebase is mature, written entirely in safe Rust (zero `unsafe` in production code), and follows defensive patterns. No critical vulnerabilities were found. The Nemesis pass discovered **6 new findings** missed by pattern-matching alone, including a confirmed logic bug in gossipsub fanout peer selection. Of 26 total findings across all passes, 19 were confirmed or partially valid, 1 was a false positive, and 6 were classified as spec-aligned design decisions.

| # | Title | Severity | Category | Status |
|---|-------|----------|----------|--------|
| **NM-G1** | **Gossipsub heartbeat fanout replenishment selects WRONG peers (inverted score filter)** | **Medium** | **Bugs — Logic Error** | **Confirmed (Nemesis)** |
| **NM-R1** | **Relay off-by-one: per-peer reservation limit allows max+1** | **Low** | **Bugs — Off-by-One** | **Confirmed (Nemesis)** |
| **NM-R2** | **Relay off-by-one: per-peer circuit limit allows max+1** | **Low** | **Bugs — Off-by-One** | **Confirmed (Nemesis)** |
| **NM-R3** | **Relay phantom reservation on accept failure (no cleanup)** | **Low** | **Bugs — State Inconsistency** | **Confirmed (Nemesis)** |
| **NM-R4** | **Relay IP rate limiter bypass on non-IP multiaddrs** | **Low** | **Security — Access Control** | **Confirmed (Nemesis)** |
| **NM-G2** | **Gossipsub blacklisted peer subscriptions processed before check** | **Low** | **Security — Access Control** | **Confirmed (Nemesis)** |
| 1 | Kad `StoreInserts::Unfiltered` default allows unvalidated record storage | Medium | Security — Input Validation | Partially Valid |
| 5 | WebSocket default `max_data_size` of 256 MiB | Medium | Security — Resource Exhaustion | Confirmed |
| 6 | Server metrics bound to 0.0.0.0:8888 without auth | Medium | Security — Information Disclosure | Confirmed |
| 14 | WebRTC-WebSys drops inbound streams on full channel (cap 4) | Medium | Concurrency — Event Loss | Confirmed |
| 15 | Floodsub has no message authentication | Medium | Security — Authentication | Confirmed |
| 2 | Gossipsub `ValidationMode::None` bypasses signatures (not default) | Low | Security — Cryptographic Misuse | Partially Valid |
| 4 | QUIC Config::new panics on TLS failure via unwrap | Low | Error Handling — Panic | Partially Valid |
| 7 | Secp256k1 DER parsing permissive (TODO for strictness) | Low | Security — Cryptographic Misuse | Partially Valid |
| 8 | ECDSA/Secp256k1 keygen uses thread_rng() vs Ed25519's OsRng | Low | Security — Cryptographic Misuse | Partially Valid |
| 10 | debug_assert! as only guard in memory transport | Low | Error Handling — Debug-only Guard | Partially Valid |
| 11 | TLS extract_single_certificate panic on invariant violation | Low | Error Handling — Panic | Partially Valid |
| 16 | Memory connection limits may use stale stats on failure | Low | Security — Resource Management | Partially Valid |
| 17 | Ignored RUSTSEC-2024-0436 (unmaintained `paste`) in deny.toml | Low | Security — Supply Chain | Partially Valid |
| 9 | Pnet XSalsa20 without MAC (spec-compliant) | Informational | Security — Design Decision | Design Decision |
| 12 | Mplex shared Mutex contention (deprecated muxer) | Informational | Concurrency — Performance | Design Decision |
| 13 | Yamux drops inbound streams beyond 256 buffer | Informational | Architecture — Resource Management | Design Decision |
| 18 | `full` feature includes `plaintext` transport | Informational | Security — Configuration | Design Decision |
| 19 | `cargo-audit` CI uses unmaintained `actions-rs` | Informational | Security — Supply Chain | Design Decision |
| 20 | Identify listen addresses without cryptographic proof | Informational | Security — Trust Model | Design Decision |
| 3 | Swarm unbounded pending_swarm_events VecDeque | — | Concurrency — Resource Exhaustion | False Positive |

## Nemesis Pass Findings (New — Iteration 3)

These findings were discovered by the Nemesis methodology (Feynman first-principles + State Inconsistency analysis) and were NOT caught by the initial pattern-matching review or the second-pass verification. They represent logic bugs and state coupling issues that require reasoning about code paths, not just scanning for known vulnerability patterns.

### NM-G1. Gossipsub heartbeat fanout replenishment selects WRONG peers (inverted score filter)
- **Severity**: Medium
- **Category**: Bugs — Logic Error
- **Location**: `protocols/gossipsub/src/behaviour.rs:2476-2477`
- **Status**: Confirmed
- **Source**: Feynman Q3 (Consistency) — "If `publish()` selects peers above threshold, why does heartbeat select below?"
- **Description**: The heartbeat's fanout replenishment code uses `score < publish_threshold` to filter candidate peers, which is the **exact inverse** of every other publish-threshold check in the codebase. The `publish()` function at line 698 correctly uses `!below_threshold(publish_threshold)` (meaning `score >= publish_threshold`). The heartbeat at line 2476 selects peers BELOW the threshold — the worst-scoring peers.
- **Evidence**:

  Heartbeat fanout replenishment (WRONG — line 2476):
  ```
  && scores.get(peer_id).map(|r| r.score).unwrap_or_default()
      < publish_threshold
  ```

  publish() fanout creation (CORRECT — line 698):
  ```
  !self.peer_score.below_threshold(p, |ts| ts.publish_threshold).0
  ```

  Fanout peer REMOVAL in same heartbeat (CORRECT — line 2445):
  ```
  peer_score < publish_threshold  // removes peers below threshold
  ```

- **Impact**:
  - **Scoring disabled** (default: `publish_threshold = 0.0`, default score = `0.0`): `0.0 < 0.0` is `false` — **no peers can ever be selected**. Fanout replenishment is a permanent no-op. Fanout for publish-only topics degrades as peers disconnect and can never be restored by the heartbeat.
  - **Scoring enabled** (typical `publish_threshold` is negative, e.g. `-50.0`): Only peers with scores below `-50.0` are selected — the lowest-quality peers are preferentially added to fanout, inverting the intended behavior.
- **Trigger Sequence**:
  1. Node publishes to a topic it is not subscribed to (fanout path)
  2. `publish()` correctly selects peers with `score >= publish_threshold`
  3. Some fanout peers disconnect
  4. Heartbeat runs → fanout has fewer than `mesh_n` peers → attempts replenishment
  5. `get_random_peers` filter: `score < publish_threshold` — selects wrong peers (or none at all)
  6. Fanout quality permanently degrades
- **Proposed Fix**:
  ```rust
  // Line 2476: change < to >=
  && scores.get(peer_id).map(|r| r.score).unwrap_or_default()
      >= publish_threshold
  ```

### NM-R1. Relay off-by-one: per-peer reservation limit allows max+1
- **Severity**: Low
- **Category**: Bugs — Off-by-One
- **Location**: `protocols/relay/src/behaviour.rs:408`
- **Status**: Confirmed
- **Source**: Feynman Q5 (Boundaries) — "What happens at exactly max_reservations_per_peer?"
- **Description**: The per-peer reservation limit check uses `>` instead of `>=`. A peer with exactly `max_reservations_per_peer` reservations passes the check (`4 > 4` is `false`) and gets one more. The global check on line 415 correctly uses `>=`.
- **Impact**: Each peer can hold `max_reservations_per_peer + 1` reservations (5 instead of 4 by default). Across many peers, this inflates the global count and could deny legitimate peers sooner.
- **Proposed Fix**: Change `>` to `>=` at line 408.

### NM-R2. Relay off-by-one: per-peer circuit limit allows max+1
- **Severity**: Low
- **Category**: Bugs — Off-by-One
- **Location**: `protocols/relay/src/behaviour.rs:534-535`
- **Status**: Confirmed
- **Source**: Feynman Q5 (Boundaries) — same pattern as NM-R1
- **Description**: Same `>` vs `>=` issue for circuit limits. A peer with exactly `max_circuits_per_peer` circuits can open one more. Global check on line 536 correctly uses `>=`.
- **Impact**: Each peer can have `max_circuits_per_peer + 1` circuits. Same inflation effect as NM-R1.
- **Proposed Fix**: Change `>` to `>=` at line 535.

### NM-R3. Relay phantom reservation on accept failure (no cleanup)
- **Severity**: Low
- **Category**: Bugs — State Inconsistency
- **Location**: `protocols/relay/src/behaviour.rs:434-437` (insert), `protocols/relay/src/behaviour.rs:475-483` (missing cleanup)
- **Status**: Confirmed
- **Source**: Feynman Q6 (Error Paths) + State Inconsistency analysis of `reservations` map mutation paths
- **Coupled Pair**: `reservations` map ↔ handler `active_reservation` state
- **Description**: When a reservation request is accepted, the behaviour optimistically inserts `(peer_id, connection_id)` into the `reservations` map at line 434-437, then sends `AcceptReservationReq` to the handler. If the handler's accept fails (peer resets substream before response is sent), it emits `ReservationReqAcceptFailed`. The behaviour's handler for this event at lines 475-483 emits an event but does NOT remove the phantom entry from `reservations`.
- **Impact**: Phantom reservations inflate the count, reducing available slots. The phantom persists until the connection closes (handler idle timeout ~10s with no active reservation), bounding sustained exploitation.
- **Proposed Fix**:
  ```rust
  handler::Event::ReservationReqAcceptFailed { error } => {
      if let hash_map::Entry::Occupied(mut peer) = self.reservations.entry(event_source) {
          peer.get_mut().remove(&connection);
          if peer.get().is_empty() {
              peer.remove();
          }
      }
      // ... emit event as before
  }
  ```

### NM-R4. Relay IP rate limiter bypass on non-IP multiaddrs
- **Severity**: Low
- **Category**: Security — Access Control
- **Location**: `protocols/relay/src/behaviour/rate_limiter.rs:47-53`
- **Status**: Confirmed
- **Source**: Feynman Q4 (Assumptions) — "What does this assume about the multiaddr?"
- **Description**: The IP-based rate limiter calls `multiaddr_to_ip(addr)` to extract an IP component. When no IP is found (DNS-only addresses, memory transport, future non-IP transports), it returns `None`, and the rate limiter defaults to `unwrap_or(true)` — allowing the request. The per-peer rate limiter still applies, but IP-based rate limiting becomes a no-op.
- **Impact**: Low in current deployments (TCP/QUIC resolve to IP before connection). Higher risk if future transports are added that don't include IP in their multiaddr representation.
- **Proposed Fix**: Change `unwrap_or(true)` to `unwrap_or(false)` — deny by default when IP cannot be extracted.

### NM-G2. Gossipsub blacklisted peer subscriptions processed before check
- **Severity**: Low
- **Category**: Security — Access Control
- **Location**: `protocols/gossipsub/src/behaviour.rs:3267-3278`
- **Status**: Confirmed
- **Source**: Feynman Q2 (Ordering) — "What if subscription processing runs before the blacklist check?"
- **Description**: When processing incoming RPC messages, subscription handling runs BEFORE the graylist/score check. There is no blacklist check in the RPC processing path at all — `blacklist_peer` only adds to a set used in `message_is_valid`. A blacklisted peer that maintains a connection can register topic subscriptions, and the floodsub forwarding path in `forward_msg` includes peers based on `connected_peers.topics` without checking the blacklist.
- **Impact**: Low practical impact — `blacklist_peer` is typically combined with swarm-level disconnection. But the API contract of "blacklist" implies full exclusion, which isn't enforced for subscription visibility or floodsub forwarding.
- **Proposed Fix**: Add blacklist check at the top of RPC handler, before subscription processing.

---

## Nemesis Pass — State Coupling Verification (No Bugs Found)

The following coupled state pairs were verified across ALL mutation paths and found to be correctly synchronized:

| Subsystem | Coupled Pair | Mutation Paths Checked | Verdict |
|-----------|-------------|----------------------|---------|
| Gossipsub | `mesh[topic]` ↔ `peer_score` (graft/prune) | 9 paths | Sound |
| Gossipsub | `mcache` ↔ `duplicate_cache` | 4 paths | Sound (different lifetimes by design) |
| Gossipsub | `connected_peers` ↔ `mesh` | 6 paths | Sound |
| Gossipsub | `subscriptions` ↔ `mesh` | 3 paths | Sound |
| Gossipsub | `fanout` ↔ `fanout_last_pub` | 3 paths | Sound (always updated together) |
| Relay | `reservations` count ↔ `reservations` map | Derived (no separate counter) | Sound by design |
| Relay | `circuits` count ↔ `circuits` map | Derived (no separate counter) | Sound by design |
| Relay | rate limiter ↔ resource counts | Intentionally decoupled | Sound by design |
| Swarm | `ConnectionCounters` ↔ pool maps | 6 paths | Sound (transient gap is safe) |
| Swarm | pending errors ↔ established map | 3 paths | Sound (clean separation) |

---

## Original Findings (Iterations 1-2)

### 1. Kad `StoreInserts::Unfiltered` default allows unvalidated record storage
- **Severity**: Medium
- **Category**: Security — Input Validation
- **Location**: `protocols/kad/src/behaviour.rs:231`
- **Status**: Partially Valid
- **Description**: `Config::new` defaults to `StoreInserts::Unfiltered`, meaning incoming PutRecord and AddProvider requests are stored without application-layer validation. The memory store caps at 1024 records / 65 KiB values, bounding resource abuse, but does not validate record semantics or provenance.
- **Impact**: A peer can insert arbitrary record content into the local DHT store within the memory limits. Combined with Sybil attacks, this enables DHT poisoning — bad records returned for legitimate key lookups. The `StoreInserts::FilterBoth` alternative exists and is documented on `Config::set_record_filtering`, but not in the crate-level docs.
- **Analysis**: Default is `Unfiltered` as confirmed in `behaviour.rs:231`. Documentation warnings exist on the `StoreInserts` enum and `set_record_filtering` method but not at the crate root (`lib.rs`). The memory store's `max_records` and `max_value_bytes` prevent unbounded resource consumption but don't validate correctness. The inbound path (`record_received` ~1891-1918) stores immediately under `Unfiltered` with no extra validation beyond TTL/expiry. This is factually accurate, though the severity is Medium rather than High because the default store limits provide some mitigation and `FilterBoth` is available.
- **Proposed Fix**: Applications should use `config.set_record_filtering(StoreInserts::FilterBoth)` and validate records before storing. Library improvement: add prominent security notes in `lib.rs` docs pointing at `StoreInserts` and DHT trust assumptions.

### 2. Gossipsub `ValidationMode::None` bypasses signatures (not default)
- **Severity**: Low (downgraded from High — not the default)
- **Category**: Security — Cryptographic Misuse
- **Location**: `protocols/gossipsub/src/config.rs` (ValidationMode enum), `protocols/gossipsub/src/protocol.rs:309-345`
- **Status**: Partially Valid
- **Description**: `ValidationMode::None` skips signature verification entirely, and the decode path treats invalid signatures as valid. However, the default is `ValidationMode::Strict`, which requires and verifies author, sequence number, and signature.
- **Impact**: Only dangerous if explicitly configured. The default `Strict` mode provides full signature verification via `verify_signature` in `protocol.rs`. Cannot be reached accidentally — requires explicit `.validation_mode(ValidationMode::None)` call.
- **Analysis**: `ProtocolConfig::default()` sets `validation_mode: ValidationMode::Strict` (protocol.rs:76-89). `ConfigBuilder::default()` inherits this. The `None` mode is documented on the enum as skipping validation. The risk is real but only for misconfigured deployments.
- **Proposed Fix**: No code change needed for defaults. Documentation could be strengthened with warnings about `None` mode in adversarial environments.

### 3. Swarm unbounded `pending_swarm_events` VecDeque
- **Status**: False Positive
- **Description**: Initial concern was that the VecDeque could grow unbounded. Subagent analysis revealed that `poll_next_event` always drains `pending_swarm_events` with `pop_front()` before polling behaviour/pool/transport, and each handler pushes at most one event per iteration. In practice, the queue never holds more than one event.
- **Analysis**: The loop in `swarm/src/lib.rs:1196-1255` checks `pop_front()` first, then polls sources which each push at most one event and `continue`. The deque is effectively a single-item buffer due to the polling discipline.

### 5. WebSocket default `max_data_size` of 256 MiB
- **Severity**: Medium
- **Category**: Security — Resource Exhaustion
- **Location**: `transports/websocket/src/framed.rs:49-50`
- **Status**: Confirmed
- **Description**: `MAX_DATA_SIZE = 256 * 1024 * 1024` (256 MiB) is the default for both max message size and max frame size. This is set on both listener and dialer paths. The limit operates at the WebSocket layer, below the muxer, so muxer frame caps (e.g., mplex's 1 MiB) do not reduce the WebSocket-level allocation.
- **Impact**: A malicious peer can send a single WebSocket message forcing up to 256 MiB allocation. Multiple connections can exhaust memory. The limit is configurable via `Config::set_max_data_size` but the default is very high for untrusted networks.
- **Analysis**: Confirmed: `framed.rs:49-50` defines `MAX_DATA_SIZE = 256 * 1024 * 1024`. The value is passed to soketto's `set_max_message_size` and `set_max_frame_size` in `framed.rs:434-438`. The `websocket::Config` wrapper exposes `set_max_data_size` for user configuration.
- **Proposed Fix**: Lower the default to a more conservative value (e.g., 16 MiB) or document the risk prominently. Users in untrusted environments should call `config.set_max_data_size(reasonable_limit)`.

### 6. Server metrics endpoint bound to 0.0.0.0:8888 without auth
- **Severity**: Medium
- **Category**: Security — Information Disclosure
- **Location**: `misc/server/src/http_service.rs:31-44`
- **Status**: Confirmed
- **Description**: The reference server binary binds its Prometheus metrics endpoint to `0.0.0.0:8888` (all interfaces) with no authentication. A misleading code comment says "Serve on localhost" while actually binding all interfaces. The bind address and port are not configurable via CLI or config file.
- **Impact**: Operational metadata (connection counts, error rates, peer statistics, build info) is exposed to any network-reachable client. While this is a reference binary (not the library), anyone deploying it without a firewall exposes reconnaissance data.
- **Analysis**: Confirmed in `http_service.rs:31-44`: `([0, 0, 0, 0], 8888).into()`. No CLI flag for metrics address in `main.rs`. Comment says "localhost" but code binds all interfaces.
- **Proposed Fix**:
```rust
// Change default to localhost
let addr: SocketAddr = ([127, 0, 0, 1], 8888).into();
```
Add `--metrics-listen-addr` CLI flag. Fix the misleading comment.

### 14. WebRTC-WebSys drops inbound streams on full channel (cap 4)
- **Severity**: Medium
- **Category**: Concurrency — Event Loss
- **Location**: `transports/webrtc-websys/src/connection.rs:50-64`
- **Status**: Confirmed
- **Description**: Inbound data channel events use `mpsc::channel(4)` with `try_send`. When the channel is full, the `RtcDataChannel` handle is dropped with only a warning log. This loses the entire inbound stream — there is no recovery path. The remote peer's SCTP channel remains open but the Rust side never wraps it.
- **Impact**: A peer opening more than 4 data channels before the async executor drains the mpsc will cause streams to be silently lost. A malicious peer can deliberately rapid-fire channel opens to trigger this. Protocols expecting all inbound streams will desynchronize.
- **Analysis**: Confirmed in `connection.rs:50-64`. `try_send` returns immediately on `is_full()`. The dropped `RtcDataChannel` is the JS handle for the new stream — `poll_inbound` never sees it. No retry or backpressure mechanism exists.
- **Proposed Fix**: Increase channel capacity or use an unbounded channel with a documented upper bound. Alternatively, explicitly close the `RtcDataChannel` when not accepted to avoid resource leaks on the browser side.

### 15. Floodsub has no message authentication
- **Severity**: Medium
- **Category**: Security — Authentication
- **Location**: `protocols/floodsub/src/protocol.rs`, `protocols/floodsub/src/layer.rs`
- **Status**: Confirmed
- **Description**: The floodsub wire format (protobuf `Message`) has no signature field. The protocol provides no authentication of message origin. The `from` field (peer ID) is self-asserted without verification. Floodsub itself is not deprecated (only `MplexConfig` → `Config` and `Floodsub` → `Behaviour` type aliases are deprecated), and there is no prominent warning about untrusted networks.
- **Impact**: Any peer can forge messages claiming any source. In untrusted networks, floodsub provides zero authenticity guarantees. Only suitable for closed/trusted environments or with application-layer signatures.
- **Analysis**: Confirmed. The protobuf schema (`generated/rpc.proto`) defines `Message` with `from`, `data`, `seqno`, `topic_ids` only — no signature. Decode path in `protocol.rs` maps `from` to `PeerId::from_bytes` without verification. Module docs reference the floodsub spec but include no security warnings.
- **Proposed Fix**: Add prominent documentation warning that floodsub is unauthenticated and unsuitable for adversarial networks. Recommend gossipsub with `MessageAuthenticity::Signed` and `ValidationMode::Strict` as the secure alternative.

### 4. QUIC Config::new panics on TLS failure via unwrap
- **Severity**: Low
- **Category**: Error Handling — Panic
- **Location**: `transports/quic/src/config.rs:79-86`
- **Status**: Partially Valid
- **Description**: `Config::new` chains `.unwrap()` on both `make_client_config`/`make_server_config` and `QuicClientConfig::try_from`/`QuicServerConfig::try_from`. Failure causes a panic at transport construction time. No fallible `try_new` alternative exists.
- **Impact**: For standard generated keypairs, this is extremely unlikely to fail. The risk is limited to exotic or corrupted key material, or future incompatibilities between rustls and Quinn. Not remotely exploitable — this is a local construction path.
- **Analysis**: Confirmed the unwrap chain in `config.rs:79-86`. `make_client_config`/`make_server_config` can fail on rcgen errors or signing failures. `QuicClientConfig::try_from` can fail on TLS/QUIC incompatibility. Both are local operations, not network-triggered.
- **Proposed Fix**: Add `Config::try_new(keypair) -> Result<Self, QuicConfigError>` that propagates errors. Keep `Config::new` as a convenience wrapper with `expect`.

### 7. Secp256k1 DER parsing permissive (TODO for strictness)
- **Severity**: Low
- **Category**: Security — Cryptographic Misuse
- **Location**: `identity/src/secp256k1.rs:117-129`
- **Status**: Partially Valid
- **Description**: `SecretKey::from_der` has a `// TODO: Stricter parsing.` comment. The current implementation uses generic ASN.1 sequence parsing (`asn1_der::typed::Sequence`) to extract raw key bytes, then validates via k256's `SigningKey::from_slice`. The DER structure itself is not validated against RFC 5915 `ECPrivateKey` format.
- **Impact**: Non-canonical DER encodings may be accepted that a strict parser would reject. However, k256 validates the scalar value, so the cryptographic key material is always valid. The risk is spec non-compliance and potential interoperability issues, not key confusion or signature bypass.
- **Analysis**: The TODO is real. The path extracts `seq.get(1)` → `Vec::load` → `try_from_bytes` (which calls `SigningKey::from_slice`). k256 enforces a valid secp256k1 scalar regardless of DER structure. Public key path uses `from_sec1_bytes` which is properly strict.
- **Proposed Fix**: Parse RFC 5915 `ECPrivateKey` explicitly (version = 1, `privateKey` OCTET STRING length 32, reject non-canonical DER). Or delegate to a crate that enforces that profile.

### 8. ECDSA/Secp256k1 keygen uses thread_rng() vs Ed25519's OsRng
- **Severity**: Low
- **Category**: Security — Cryptographic Misuse
- **Location**: `identity/src/ecdsa.rs:96-100`, `identity/src/secp256k1.rs:94-98`
- **Status**: Partially Valid
- **Description**: ECDSA P-256 and secp256k1 key generation use `rand::thread_rng()`, while Ed25519 uses `rand::rngs::OsRng`. Both are CSPRNGs in Rust's `rand` crate — `thread_rng()` is seeded from OS entropy. The inconsistency is real but `thread_rng()` is not "insecure" in the standard Rust ecosystem.
- **Impact**: Marginal. `thread_rng()` is a thread-local ChaCha20-based CSPRNG seeded from `getrandom`. The risk is theoretical (if the CSPRNG state were compromised, e.g., via fork without re-seeding on exotic platforms). This is a hardening preference, not a vulnerability.
- **Analysis**: Ed25519 in `ed25519.rs:183-189` uses `OsRng`. ECDSA in `ecdsa.rs:96-100` and secp256k1 in `secp256k1.rs:94-98` both use `thread_rng()`. The inconsistency is factual.
- **Proposed Fix**: Align all key generation to use `OsRng` for consistency:
```rust
// In ecdsa.rs and secp256k1.rs
pub fn generate() -> SecretKey {
    SecretKey(SigningKey::random(&mut rand::rngs::OsRng))
}
```

### 10. debug_assert! as only guard in memory transport
- **Severity**: Low
- **Category**: Error Handling — Debug-only Guard
- **Location**: `core/src/transport/memory.rs:210`, `core/src/transport/memory.rs:401`
- **Status**: Partially Valid
- **Description**: Two `debug_assert!(val.is_some())` calls after `HUB.unregister_port()` are the only guards for hub state consistency. In release builds, these are stripped. If the invariant fails, execution continues — the listener path still closes the receiver, and the drop path proceeds normally. No UB, but inconsistent hub state could go undetected.
- **Impact**: If the invariant is violated in release mode (port already unregistered), the hub state may have leaked entries or logic bugs that are only caught in debug builds. The memory transport is not documented as test-only, though it is primarily used for testing and in-process setups.
- **Analysis**: Confirmed the two sites at `memory.rs:210` and `memory.rs:401`. Both call `HUB.unregister_port()` and only assert the result in debug mode. In release, a `None` return is silently ignored.
- **Proposed Fix**: Replace `debug_assert!` with explicit handling:
```rust
if HUB.unregister_port(&listener.port).is_none() {
    tracing::warn!("Port was already unregistered from hub");
}
```

### 11. TLS extract_single_certificate panic on invariant violation
- **Severity**: Low
- **Category**: Error Handling — Panic
- **Location**: `transports/tls/src/upgrade.rs:128-136`
- **Status**: Partially Valid
- **Description**: `extract_single_certificate` panics if `state.peer_certificates()` does not return exactly one certificate. The custom verifier in `verifier.rs:206-224` enforces exactly one end-entity certificate (no intermediates) and rejects violations before the handshake completes. So a remote peer cannot trigger this panic through normal operation.
- **Impact**: The panic is a defensive invariant, not reachable from a remote attacker under the current verifier. The risk is limited to: (a) a rustls behavior change that breaks the invariant, or (b) someone replacing the verifier without maintaining the constraint. For robustness, an error return would be preferred over a panic.
- **Analysis**: The verifier's `verify_presented_certs` in `verifier.rs:206-224` returns `Err(rustls::Error::General(...))` if intermediates are non-empty. A successful handshake guarantees exactly one cert. The panic in `upgrade.rs:128-136` is an internal assertion that should never fire with the current verifier.
- **Proposed Fix**: Replace `panic!` with an error variant for robustness:
```rust
let Some([cert]) = state.peer_certificates() else {
    return Err(certificate::ParseError::InvalidCertificateCount);
};
```

### 16. Memory connection limits may use stale stats on failure
- **Severity**: Low
- **Category**: Security — Resource Management
- **Location**: `misc/memory-connection-limits/src/lib.rs:128-143`
- **Status**: Partially Valid
- **Description**: Memory stats are cached with a 100ms staleness window. When `memory_stats()` returns `None`, the code logs a warning but does not update `last_refreshed`, causing every subsequent `check_limit` call to retry (and warn). The cached `process_physical_memory_bytes` stays at the last successful value (or constructor default) indefinitely.
- **Impact**: If `memory_stats()` consistently fails (platform issue, containerized environment without /proc), admission decisions use arbitrarily stale data. This could either over-admit (if cached value is low from startup) or over-deny (if cached value was high before the failure started).
- **Analysis**: Confirmed in `lib.rs:128-143`. On `None`, `last_refreshed` is not updated, so the staleness check fires every poll. The cached `process_physical_memory_bytes` is never reset or invalidated.
- **Proposed Fix**: Update `last_refreshed` on failure to rate-limit retries. Consider a policy for persistent failures (e.g., deny new connections after N consecutive failures):
```rust
let Some(stats) = memory_stats::memory_stats() else {
    tracing::warn!("Failed to retrieve process memory stats");
    self.last_refreshed = now; // rate-limit retries
    return;
};
```

### 17. Ignored RUSTSEC-2024-0436 (unmaintained `paste`) in deny.toml
- **Severity**: Low
- **Category**: Security — Supply Chain
- **Location**: `deny.toml:15-17`
- **Status**: Partially Valid
- **Description**: RUSTSEC-2024-0436 is an **informational** advisory flagging the `paste` crate as unmaintained. It is not a memory-safety CVE. The ignore entry has no comment explaining the rationale or tracking migration.
- **Impact**: Low immediate risk (no exploit). The concern is supply-chain hygiene: an unmaintained dependency may accumulate unfixed bugs over time. Without a comment, reviewers cannot assess when the ignore was added or whether migration is planned.
- **Analysis**: Confirmed the ignore entry at `deny.toml:15-17` with no accompanying comment. RUSTSEC-2024-0436 is an unmaintained-crate advisory, not a vulnerability with a patch.
- **Proposed Fix**: Add a comment explaining the ignore:
```toml
ignore = [
    # RUSTSEC-2024-0436: `paste` is unmaintained. No security vuln, tracked for migration.
    "RUSTSEC-2024-0436",
]
```

### 9. Pnet XSalsa20 without MAC (spec-compliant design decision)
- **Severity**: Informational
- **Category**: Security — Design Decision
- **Location**: `transports/pnet/src/lib.rs`, `transports/pnet/src/crypt_writer.rs`
- **Status**: Design Decision
- **Description**: Pnet uses XSalsa20 encryption without a MAC, providing confidentiality but not integrity. This is **intentional and spec-compliant**: the libp2p PSK spec explicitly states that integrity is provided by the "regular cryptographic layer above" (Noise/TLS). The PSK layer is designed for double-encryption, not as a standalone security mechanism.
- **Analysis**: The spec states: *"This allows the PSK layer to provide only above security guarantee, and for example not worrying about authenticity of the data. Possible replay attacks will be caught by the regular cryptographic layer above PNs layer."*
- **Proposed Fix**: Document in crate-level docs that pnet provides encryption only, and integrity must come from the upper security layer (Noise/TLS).

### 12. Mplex shared Mutex contention (deprecated muxer)
- **Severity**: Informational
- **Category**: Concurrency — Performance
- **Location**: `muxers/mplex/src/lib.rs`
- **Status**: Design Decision
- **Description**: All mplex substreams share `Arc<Mutex<Multiplexed<C>>>`. This is a known contention point under high concurrency. Mplex is effectively deprecated in the ecosystem — the `libp2p` meta-crate has removed the `mplex` re-export, and yamux is the recommended replacement.
- **Analysis**: The `MplexConfig` type alias is deprecated, and ecosystem guidance recommends yamux. Redesigning the lock architecture is not warranted for a deprecated protocol.

### 13. Yamux drops inbound streams beyond 256 buffer (design decision)
- **Severity**: Informational
- **Category**: Architecture — Resource Management
- **Location**: `muxers/yamux/src/lib.rs:62-67, 140-145`
- **Status**: Design Decision
- **Description**: `MAX_BUFFERED_INBOUND_STREAMS = 256` is a hardcoded constant. When exceeded, streams are dropped with a `tracing::warn!`. The constant is not configurable via the public API. The value is chosen to match ACK backlog behavior in `rust-yamux` for protocol compatibility.
- **Analysis**: Drops are logged. Remote peer sees resets (normal yamux semantics). 256 is reasonable for typical P2P workloads. The design trades potential stream loss for bounded memory usage.
- **Proposed Fix**: Optionally expose as a configurable parameter on `Config` for high-throughput applications.

### 18. `full` feature includes `plaintext` transport (design decision)
- **Severity**: Informational
- **Category**: Security — Configuration
- **Location**: `libp2p/Cargo.toml` (features.full)
- **Status**: Design Decision
- **Description**: `full` includes all features including `plaintext`. However, `plaintext` is not default (no features are enabled by default). Plaintext requires explicit API usage — it cannot be "accidentally" activated just by depending on `full`. The concern is ergonomic, not a default-insecure configuration.
- **Analysis**: No `default` features in `libp2p/Cargo.toml`. Plaintext must be explicitly wired into the transport stack via builder API.

### 19. `cargo-audit` CI uses unmaintained `actions-rs` (informational)
- **Severity**: Informational
- **Category**: Security — Supply Chain
- **Location**: `.github/workflows/cargo-audit.yml`
- **Status**: Design Decision
- **Description**: `actions-rs/audit-check@v1` is from the unmaintained `actions-rs` organization. This is a CI-only concern — no impact on production code. The risk is that the unmaintained GitHub Action could become a supply-chain attack vector if the organization is compromised.
- **Proposed Fix**: Migrate to a maintained alternative (e.g., `rustsec/audit-check` or direct `cargo audit` invocation).

### 20. Identify listen addresses without cryptographic proof (spec-aligned)
- **Severity**: Informational
- **Category**: Security — Trust Model
- **Location**: `protocols/identify/src/protocol.rs:172-183, 230-243`
- **Status**: Design Decision
- **Description**: Identify accepts self-reported listen addresses when no signed peer record is present. When a valid `signedPeerRecord` exists, it overrides the unverified `listenAddrs` and provides cryptographic binding. The fallback to unverified addresses is aligned with the libp2p identify spec.
- **Analysis**: `Info::try_from` in `protocol.rs:230-243` prefers signed peer records when available. The `parse_listen_addrs` fallback (`protocol.rs:172-183`) handles cases without signed records. Push updates (`PushInfo`) don't mirror signed-record logic.
- **Proposed Fix**: Applications should prefer signed peer records for security-critical address decisions. Consider documenting the trust model in identify crate docs.

## Cross-Cutting Observations

### No `unsafe` Code in Production
Zero `unsafe` blocks were found across all production source files in the repository. The only occurrence is in `swarm/benches/connection_handler.rs` (benchmark code, lines 22-27). All cryptographic operations delegate to well-maintained dependencies (`ed25519-dalek`, `ring`, `k256`, `p256`, `snow`, `rustls`).

### Dependency Trust Chain
Cryptographic TCB: `ed25519-dalek`, `ring`, `k256`, `p256`, `sha2`, `hkdf`, `snow`, `rustls`, `rcgen`. These are well-audited Rust crates. `cargo-deny` enforces advisory checks, license compliance, and source restrictions (no unknown registries/git sources).

### Resource Exhaustion Defenses
Most protocols implement message size limits at the codec layer:
- Gossipsub: ~64 KiB default
- Kad: 16 KiB packets
- Relay: 4 KiB messages + reservation/circuit rate limits
- Identify/DCUtR: 4 KiB
- Floodsub: 2 KiB
- Ping: 32 bytes fixed
- Noise: 65535 byte frames (u16 prefix)
- WebSocket: 256 MiB (high default — see Finding #5)

Connection limits must be enforced by the application via `libp2p-connection-limits` and/or `libp2p-memory-connection-limits` behaviours — the swarm does not impose global limits by default.

### CI Security Posture
Strong: `RUSTFLAGS='-Dwarnings'`, clippy on stable+beta, `cargo-deny` for advisories/licenses/bans/sources, semver-checks, MSRV enforcement, lockfile consistency, protobuf codegen drift detection. Daily `cargo-audit` cron. Missing: no fuzzing targets or `cargo-fuzz` integration.
