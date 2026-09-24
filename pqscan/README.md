# pqscan — post-quantum readiness scanner

`pqscan` tells you whether a host's secure services use **post-quantum key
exchange** (ML-KEM). It runs a real TLS 1.3 handshake, offers the post-quantum
hybrid groups, and reports which one the server actually negotiates — the defense
against **Harvest-Now-Decrypt-Later (HNDL)**, where an attacker records encrypted
traffic today to decrypt once quantum computers can break classical key exchange.

Written in Go with the **standard library only** — no third-party dependencies.

## Quick start

```sh
# CLI
go run ./cmd/pqscan cloudflare.com
go run ./cmd/pqscan --json example.com
go run ./cmd/pqscan --selftest        # verify the engine against a local PQC server

# Web app (self-contained binary; serves UI + POST /api/scan)
go run ./cmd/pqscan-web --addr :8080
```

Exit codes (CLI): `0` ready, `1` not ready, `2` usage error, `3` undetermined.

## What it checks

- **TLS services** (Phases 1–2), by default **HTTPS/443**; scan more with
  `--services` (or `--services all`):
  - implicit TLS: `HTTPS`, `SMTPS`, `IMAPS`, `POP3S`, `FTPS`, `LDAPS`, `DoT`,
    `MQTT`, `AMQP`, `MongoDB`, `Redis`, `Syslog-TLS`;
  - STARTTLS: `SMTP` (25), `SMTP-submission` (587), `IMAP` (143), `POP3` (110),
    `FTP` (21), `PostgreSQL` (5432).
- **SSH** (Phase 3), on port 22 — covers SSH, SFTP, SCP, and Git-over-SSH, which
  all run over the SSH transport. It reads the server's cleartext `KEXINIT` and
  reports the post-quantum key-exchange methods it advertises
  (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`).
- A **support matrix** across the ML-KEM key-exchange groups: `X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, and the deprecated
  `X25519Kyber768Draft00` (best-effort; a negative for the legacy group is not
  authoritative).
- TLS version, cipher suite, and the certificate's **signature algorithm** +
  expiry (context — post-quantum certificate signatures are essentially not
  deployed yet, and forged signatures are not an HNDL threat).

Roadmap (see the plan): Phase 4 QUIC/HTTP-3, Phase 5 IKEv2/IPsec.

## How it works

For each post-quantum group, `pqscan` sends a hand-crafted TLS 1.3 ClientHello
offering that group **and** a classical fallback (X25519), then reads which group
the server selects from the (unencrypted) ServerHello and disconnects. It never
completes the handshake and never uses the shared secret. Valid ML-KEM key shares
are generated at runtime with the standard `crypto/mlkem` package, so a server
cannot reject the offer as malformed. Go's `crypto/tls` natively speaks
`X25519MLKEM768`; the other groups are hand-crafted because no TLS library will
*offer* a group it cannot itself perform.

The scanner **self-calibrates**: before trusting any verdict it probes a local,
in-process TLS server that is known to support `X25519MLKEM768`. If the engine
cannot detect PQC there, the web server refuses to start (`--selftest` runs the
same check from the CLI).

> Note: detecting *external* PQC requires network egress that carries the
> post-quantum handshake. Some sandboxed environments negotiate only classical
> groups regardless of the target; there, external scans read "not ready" even for
> PQC-enabled sites, while the hermetic self-calibration still confirms the engine.

## Standards & references

- **TLS 1.3** — [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446); IANA
  [TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/) registry.
- **Hybrid key exchange in TLS 1.3** — `draft-ietf-tls-hybrid-design`; the ML-KEM
  groups `X25519MLKEM768` / `SecP256r1MLKEM768` / `SecP384r1MLKEM1024` —
  `draft-ietf-tls-ecdhe-mlkem`.
- **NIST PQC** — [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) (ML-KEM),
  [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) (ML-DSA),
  [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) (SLH-DSA), FIPS 206/draft (FN-DSA).
- **SSH** — [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253); PQC KEX
  `sntrup761x25519-sha512` and `draft-ietf-sshm-mlkem-hybrid-kex`
  (`mlkem768x25519-sha256`) — Phase 3.
- **QUIC/TLS** — [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001) — Phase 4.
- **IKEv2 multiple key exchange** — [RFC 9370](https://datatracker.ietf.org/doc/html/rfc9370) — Phase 5.
- **NSA CNSA 2.0** migration timelines.

## FAQ

**1. What does "quantum-safe" mean here?** That the service's TLS **key exchange**
can use ML-KEM (post-quantum). That is the part with real urgency, because recorded
handshakes are what HNDL harvests.

**2. How do you *prove* ready-or-not?** By negotiation. The server authoritatively
selects the key-exchange group in a live handshake; we offer post-quantum first and
read its choice. It is the server's real behavior, not a claim.

**3. What is Harvest-Now-Decrypt-Later?** Recording encrypted traffic today to
decrypt it later, once a quantum computer can break classical (RSA/ECDH) key
exchange. Post-quantum key exchange defeats it.

**4. Which NIST PQC algorithms are covered?** Key exchange (ML-KEM) is probed
directly across its TLS groups. Signatures (ML-DSA/SLH-DSA/FN-DSA) are reported via
the certificate's signature algorithm; they are near-zero deployed and not an HNDL
risk.

**5. Which services are supported?** Phase 1: HTTPS. Roadmap: other TLS services,
SSH/SFTP/SCP, QUIC/HTTP-3, IKEv2.

**6. What does "hand-craft the ClientHello" mean, and is it safe?** We build the
handshake's first message byte by byte to offer groups a TLS library won't offer on
its own, then read the server's pick. It needs no cryptography beyond a valid
ML-KEM key (from `crypto/mlkem`), uses the public TLS 1.3 format, and is the
standard technique used by TLS scanners.

**7. Why not just use OpenSSL or a TLS library?** A library only offers groups it
can itself perform; Go's does only `X25519MLKEM768`. Hand-crafting lets us probe
every group (and future ones) precisely, with no heavy dependency.

**8. Why Go?** Its standard `crypto/tls` speaks `X25519MLKEM768` natively and
`crypto/mlkem` mints valid keys; strong concurrency and a single static binary suit
a scanner. (Python is a viable fallback; Node cannot offer ML-KEM natively.)

**9. Is generating/reusing the ML-KEM key safe?** Yes. We discard the shared secret
and never decapsulate, so the key need not be secret; `crypto/mlkem` generates a
fresh valid one per probe.

**10. Why is a "not ready" verdict trustworthy?** We offer post-quantum *first* with
a valid key, so a classical result means the server would not use PQC in practice.
Self-calibration confirms the engine reads a known PQC server correctly first.

**11. Does it check certificate signatures?** It reports the served certificate's
signature algorithm. PQC certificate signatures are essentially undeployed today.

**12. Is this a scanning/hacking tool? Ethics & limits.** No. It reads only public
handshake metadata, never exploits anything, and refuses non-public targets
(loopback, private, link-local, cloud-metadata) with rate limiting. Scan only
endpoints you are entitled to check.

**13. What does a result *not* tell me?** It reflects this endpoint at this moment;
large sites behind many servers can vary, and configurations change.

**14. Hybrid vs pure PQC?** All current TLS PQC groups are *hybrid* — a classical
group (X25519/P-256) combined with ML-KEM — so security holds even if one component
is broken. That is the recommended posture today.

**15. Who is this for?** PQC-migration engineers, DevOps/SRE (CI gating),
compliance/GRC and auditors, pentesters and vendor-risk assessments, sysadmins of
mail/SSH/DB servers, and anyone learning about PQC and HNDL.
