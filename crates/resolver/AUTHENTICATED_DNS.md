# Authenticated authoritative DNS

This branch extends the authoritative transport configuration introduced by Grace
Helena Cimaszewski. It uses Hickory's existing DoT/QUIC transports and Rustls verifier to
require authenticated DNS-over-TLS (DoT) or DNS-over-QUIC (DoQ) for configured
endpoints.

## Configuration and startup validation

`RecursiveConfig::forced_encrypted_authoritatives` names a JSON policy file.
`ForcedEncryptedAuthoritativeConfig` represents that file; conversion to
`ForcedEncryptedAuthoritativePolicy` validates and indexes it before resolution
starts.

Each `servers` entry has:

| Field | Meaning |
|---|---|
| `name` | Expected concrete DNS identity, used for certificate verification and SNI |
| `address` | Explicit IPv4 or IPv6 endpoint address |
| `protocol` | `dot` with TLS support, or `doq` with QUIC support enabled in the build |
| `trust_anchor` | One or more PEM certificates used as the endpoint's explicit trust roots |

Names are compared case-insensitively with a trailing dot ignored for TLS identity.
PEM parsing accepts certificate bundles but rejects malformed blocks or unrelated
material. Startup parsing does not verify a remote certificate: signature, DNS
name and validity verification occur during the Rustls handshake. Global
opportunistic verification settings do not replace this endpoint verifier.

Equivalent entries are deduplicated. Conflicting identities for an address,
incompatible trust settings for one server name, unsupported protocols, missing
addresses and invalid trust material cause startup failure.

## Two authorization modes

Endpoint requirements alone protect connections to listed addresses. They do not
prove that an endpoint is authorized to answer for a particular customer zone.
There are two ways to provide that authorization:

1. **Trusted local bindings.** Optional `zones` entries associate a zone with
   configured server names. The most specific matching zone wins. Its explicit
   addresses form a required-authentication pool and bypass parent referrals.
2. **Authenticated referrals.** Set `authenticated_referrals` to `true`, omit
   `zones` or leave it empty, and configure every root address and required server
   endpoint. Hickory follows real referrals through authenticated pools. The
   authenticated parent supplies the child's NS identity; the selected NS name
   and address must match a configured endpoint before connection.

These modes cannot be combined in one policy. Omitting `authenticated_referrals`
preserves its default `false` value and the earlier binding behavior.

In referral mode, out-of-zone nameserver A/AAAA lookups use authenticated
recursion. CNAME targets are resolved under the same protection, and DS queries
go to the authenticated parent. In-bailiwick missing-glue cycles fail closed if an
address cannot be obtained; recursion limits bound external cycles. This is
curated channel authentication, not automatic public-Internet endpoint discovery.

## Connection, retry and cache invariants

- Required endpoints use their configured protocol on port 853: DoT over TCP
  or DoQ over UDP, with the configured DNS identity. DoQ cannot fall back to DoT
  or plaintext, and DoT cannot substitute DoQ.
- Required pools filter endpoints before ordering, racing or retrying. They may
  retry another approved secure endpoint but must not fall back to plaintext.
- Per-endpoint Rustls configurations contain the supplied trust roots. Their
  immutable identities are retained by connection states and cache keys.
- A live connection authenticated under another trust configuration, including
  opportunistic verification, cannot satisfy the current endpoint requirement.
- Connection-cache keys include full endpoint parameters and TLS trust identity.
- Ordinary responses and authenticated responses/referrals use separate caches.
  Policies are immutable for the resolver's lifetime; restart to replace a policy.
- Typed security errors survive recursive lookup handling instead of being
  mistaken for an absent zone cut or a reason to try an insecure path.

The optional `connect_timeout_ms` recursor setting bounds connection establishment,
including TLS authentication in either transport. It must be positive. When absent,
existing timeout defaults remain in effect. A connection budget shorter than a client's DNS
deadline leaves time to try an approved backup; a full pool deadline still bounds
overall retries.

## Tests and code map

| File | Responsibility |
|---|---|
| `src/recursor/mod.rs` | Raw configuration, validation, trust parsing and runtime policy |
| `src/recursor/handle.rs` | Policy lookup, pools, referrals, dependencies and response-cache separation |
| `src/connection_provider.rs` | Native DoT/DoQ endpoint guards, verifier selection and typed failures |
| `src/name_server.rs` | Connection selection and trust-aware reuse |
| `src/name_server_pool.rs` | Approved endpoint filtering, deadlines and retries |
| `src/recursor/security_tests.rs` | Mock-provider selection/cache/referral tests |
| `src/recursor/tests/authenticated_dot.rs` | Real loopback TLS verification and timeout tests |
| `src/recursor/tests/authenticated_doq.rs` | Real QUIC certificate, SNI/ALPN, reuse, timeout and no-fallback tests |

Run the library checks from the repository root:

```sh
cargo test --locked --offline -p hickory-resolver --lib \
  --features recursor,serde,toml,dnssec-ring,tls-ring
```

To include strict DoQ, enable a QUIC feature (which also enables TLS):

```sh
cargo test --locked --offline -p hickory-resolver --lib \
  --features recursor,serde,toml,dnssec-ring,quic-ring

cargo build --locked --offline -p hickory-dns --bin hickory-dns --no-default-features \
  --features recursor,dnssec-ring,quic-ring
```

`quic-aws-lc-rs` is the alternative QUIC crypto-provider feature. A build without
QUIC support still rejects `doq` policies at startup; it does not change their
meaning to DoT or plaintext. Keep the same `name`, `address` and `trust_anchor`
fields when changing an endpoint's required `protocol` from `dot` to `doq`.
The authority must actually serve DoQ on UDP 853 and negotiate the `doq` ALPN.

QUIC uses the endpoint's independent Rustls verifier, not the shared opportunistic
verifier. Required QUIC connections disable early data, wait for the authenticated
handshake and carry the same immutable trust identity used for DoT reuse checks.
Binding errors, unavailable runtime QUIC support and handshake failures remain
typed security failures. Protocol checks also run before connection creation.

Real QUIC tests use unprivileged loopback ports through a datagram address adapter.
They verify valid certificates, wrong names, wrong CAs, expired certificates,
bounded stalled handshakes, authenticated NXDOMAIN, verified connection reuse,
real certificate-failure failover and certificate verification after reconnecting.
Independent plaintext and opportunistic QUIC queries establish that rejection
tests use reachable servers. Decision tests additionally cover approved backup
selection, referrals with and without glue, CNAME dependencies, protocol filtering
and rejection of weak or differently trusted cached connections.

The earlier Docker/ACME and performance result folders describe the DoT build
tested at that time. These new QUIC tests do not turn those historical measurements
into DoQ issuance or performance results.

The certificate material under `tests/test-data/authenticated-dot` is explicitly
public test data. Its checked-in server key must never be used for a deployment.
Do not publish operational lab private keys or Certbot account directories.

## Scope and known limitation

Authenticated transport protects answers and referrals in transit from trusted
servers. It does not add DNSSEC signatures, set an authenticated-data claim for
unsigned records, remove trust in the DNS provider, or implement the complete
Crypto-DV domain-owner policy framework. Signed SVCB discovery, `_deleg`/DELEG
processing, automatic trust rotation and additional dependency mechanisms remain
outside this implementation.

The local availability experiment found a glueless-failover limitation:
`append_ips_from_lookup` can return the first failed authenticated address
dependency before trying a reachable, approved backup's dependency. Direct local
binding failover and referral-based address discovery exercise different paths.
The TODO beside that early return records the required follow-up: try other
complete authenticated candidates, while still rejecting insecure fallback.
