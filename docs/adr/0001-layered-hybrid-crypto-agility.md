# ADR 0001 — Crypto-agile combiner: post-quantum hybrids first-class, classical hybrid compat-only

**Status:** Accepted (Sylvain Cormier, 2026-06-22)
**Scope:** `paraxiom-pqc` (foundation), `qssl`, `qssh`, `pqtg`, and the Transparence/QH interop surfaces.
**Supersedes the earlier draft of this ADR**, which sloppily conflated "hybrid" with the
classical kind.

## Context

The question was framed as "hybrid vs no-hybrid." That binary is wrong, because **"hybrid"
is three different things** and the stack already ships one of them:

- **PQTG is hybrid today** — but **QKD ⊕ PQC**, not classical ⊕ PQC. See
  `quantumharmony/docs/QBER_ATTESTATION_ARCHITECTURE.md`:
  `fn mix_keys(qkd_key, pqc_key) -> [u8;32]` — *"Even if QKD key is compromised, PQC
  component remains quantum-safe."* No RSA/ECDSA/X25519 anywhere.

The thing that was rejected (X25519Kyber768 for TLS) and that Paraxiom's CCCS advisory
attacks ("Residual Classical Vulnerability…") is the **classical** component — never
"hybrid" as a concept. A hybrid of two post-quantum mechanisms gives the break-survivability
benefit of hybrid **without** reintroducing classical crypto.

## The taxonomy (this is the whole decision)

| Flavor | Mixes | Reintroduces classical? | Status |
|---|---|---|---|
| **classical ⊕ PQC** | X25519/ECDSA + PQC | **Yes** — residual classical vuln | compat-only, opt-in |
| **QKD ⊕ PQC** | ETSI-014 physics key + PQC | No | first-class (PQTG ships it) |
| **PQC ⊕ PQC** | two independent PQC families | No | first-class |
| **pure single-PQC** | one PQC primitive | No | first-class (default) |

## Decision

There is **no global "hybrid on/off."** Instead: a **crypto-agile combiner** in
`paraxiom-pqc`, with the mechanism set **selectable per link/role**. Post-quantum hybrids
are first-class; **classical ⊕ PQC is the only mode gated behind opt-in "compatibility,
when externally mandated" — never the default, never sold as a security upgrade.**

Selectable modes:

- **pure single-PQC** — default for owned / low-stakes links. Simplest, smallest, easiest
  to Lean-verify.
- **PQC ⊕ PQC** — break-hedge with zero classical, for high-assurance owned links.
- **QKD ⊕ PQC** — where QKD hardware exists (PQTG / KirQ). Strongest "no classical" story.
- **classical ⊕ PQC** — opt-in compatibility only (a partner/RFP that hard-requires
  X25519MLKEM768-style hybrid). Clearly labelled as a compatibility concession.

Break-survivability without classical is achieved by (a) **crypto-agility** — rotate the
PQC algorithm fast — and/or (b) a **PQC⊕PQC** or **QKD⊕PQC** combiner where the assurance
justifies it.

## Grounded current state (2026-06-22)

- `paraxiom-pqc`: pure-PQC primitives only — KEM `MlKem{512,768,1024}`; SIG `MlDsa{44,65,87}`,
  `SlhDsaShake{128f,256s}`, `Falcon{512,1024}`. **No classical, no combiner, no X.509/DER.**
- Assumption diversity available **today** for PQC⊕PQC **signatures**: lattice
  (ML-DSA/Falcon) **⊕** hash-based (**SLH-DSA**) — genuinely different hardness, so a lattice
  break is survived by the hash-based half. This is the strong, immediately-buildable PQC⊕PQC.
- PQC⊕PQC **KEM** diversity is NOT yet possible: all KEMs here are lattice (ML-KEM).
  Real diversity needs a non-lattice KEM (e.g. **HQC**, NIST's 2025 backup pick, code-based).
- `qssl`: own `bincode` cert format; `pqtg`: QKD⊕PQC `mix_keys`; `qssh`: own host-key format.

## Consequences

- Classical primitives are needed **only for the compat mode**, and stay off every default
  path. When added, they MUST be pure-Rust (`x25519-dalek`/`ed25519-dalek`) to keep zero-C.
- The native (`bincode`) format is **not** removed; it stays default on owned links.
- PQC⊕PQC sig hybrid (ML-DSA/Falcon ⊕ SLH-DSA) is buildable now; a code-based KEM (HQC) is a
  prerequisite for a meaningful PQC⊕PQC **KEM** hybrid.
- Browser-edge stays classical TLS until browsers ship PQC — out of our hands; targets are
  server↔server and partner links.

## Plan (foundation-up)

1. `paraxiom-pqc`: **combiner API** — KDF over an ordered set of shared secrets / signatures,
   mechanism set selected by config (the agility core).
2. `paraxiom-pqc`: **PQC⊕PQC** combiners — sig (ML-DSA/Falcon ⊕ SLH-DSA) now; KEM after HQC.
3. `paraxiom-pqc`: optional pure-Rust **classical** primitives (X25519, Ed25519) — for the
   classical⊕PQC compat mode ONLY, behind a feature flag.
4. `paraxiom-pqc`: optional **X.509/LAMPS** DER encoding (standalone PQC + composite OIDs)
   alongside the native format, for interop-facing surfaces.
5. Wire the combiner into `pqtg` (formalise its QKD⊕PQC as one combiner instance), `qssl`
   (selectable modes + X.509 interop), `qssh` (config-driven mechanism).
6. Transparence/QH: server↔server over qssl (pure-PQC or PQC⊕PQC); classical only if an RFP
   mandates it.

## Non-goals

- A global hybrid on/off switch — replaced by the per-link selector.
- Removing the verified native format.
- Treating classical⊕PQC as anything but a compatibility concession.
- Browser-edge PQC before browser support exists.

---

## Addendum — 2026-08-08: Simon/DCP lattice claim elevates the KEM-diversity item

**Trigger.** D. R. Simon (AWS), 2026-08-06, posted a preliminary-draft claim of a polynomial-time
quantum algorithm for the Dihedral Coset Problem (Cryptology ePrint 2026/1591); a peer-reviewed
CRYPTO 2026 result (Wen–Zheng, *Module Learning With Errors and Structured Extrapolated Dihedral
Cosets*) supplies the Module-LWE ↔ structured-EDCP link. If it holds and the reductions compose at
real parameters, the family it touches is **Module-LWE — i.e. ML-KEM.**

**Status (this ADR's honesty policy applies):** credible but **unverified — preliminary draft, sketch
proofs, no attack costed against any NIST parameter set. Nothing standardized is broken. Do NOT pause
ML-KEM** (HNDL remains the real, dated clock).

**What it changes.** It converts the "PQC⊕PQC KEM diversity needs a code-based KEM" item (already
flagged above, §"Grounded current state" + Plan step 2) from a *nice hedge* into a **named
concentration risk**: every KEM in the stack — `paraxiom-pqc` (`MlKem{512,768,1024}` only) **and PQTG
(hardcoded `KemAlgorithm::MlKem768`, `pq-transport-gateway/src/crypto.rs:30`)** — rests on the single
Module-LWE assumption. Our **signatures already have family diversity** (lattice ML-DSA/Falcon ⊕
hash-based SLH-DSA — *untouched* by this claim); the gap is **KEM-only.**

**Decision (extends, does not change, this ADR):**
1. **Add a code-based KEM — HQC** (NIST's 2025 code-based backup; handshake-sane key sizes) as
   `KemAlgorithm::Hqc*`, activating the **ML-KEM ⊕ HQC** PQC⊕PQC KEM combiner (Plan step 2). Classic
   McEliece only as a conservative *archive* option (~1 MB keys — not for a per-connection handshake).
2. **Step 0 / gating unknown — a pure-Rust HQC.** The zero-C discipline is a hard constraint and
   pure-Rust HQC is far less mature than `ml-kem`. Confirm an acceptable pure-Rust implementation
   exists before committing effort; if none does, surface it — do not paper over it.
3. **PQTG:** source `KEM_ALG` from config instead of the `crypto.rs:30` const; generalize the
   ML-KEM-768 length constants; negotiate the KEM in the handshake. Thin change — the family lives in
   `paraxiom-pqc`. Reuse PQTG's existing `mix_keys` KDF as the combine primitive.
4. **Sequencing:** not urgent (nothing costed). Tee up; don't let it pull focus from the 90-day gate.

**Audit relevance (2026-08 PQTG + `paraxiom-pqc` audits).** Disclose proactively, in the spirit of the
BeatQuantum scope letter's §2/§4: the KEM layer is single-family (Module-LWE); the Simon claim is the
live pressure on it; the mitigation is the ML-KEM ⊕ HQC agility roadmap above. This is a **known
limitation with a documented mitigation path, not a defect** — and it strengthens the honesty posture
the evaluation rewards. Relevant to BeatQuantum (PQTG) and to the crypto-core audit shortlist
(Trail of Bits / NCC Group / Quarkslab).

### Step 0 result — 2026-08-08 spike: the HQC mitigation is directionally right but ecosystem-gated

A web spike answered the gating question above. **There is no usable pure-Rust HQC today:**
- **RustCrypto** (source of our pure-Rust `ml-kem`) has **no HQC** crate.
- The only HQC crate, **`pqcrypto-hqc`**, is **C bindings to PQClean** (breaks zero-C) **and** carries
  **RUSTSEC-2026-0168** ("unlikely to receive further updates or fixes"). A non-starter for a zero-C, audited core.
- HQC's **side-channel surface is actively hot** (2025: timing leak in the deterministic-re-encryption
  rejection sampling *even with constant-time decoders*; single-trace power recovery of HQC-128 from
  ~3,500 traces, ePrint 2025/2162). A safe pure-Rust implementation is research-grade, not a port.
- HQC is **not yet final FIPS** (NIST-selected Mar 2025; finalization ~2026–2027) — a moving spec.

**Consequence (this is the honest audit answer to "is the mitigation real?"):** do **not** "add HQC now."
The mitigation that ships now is the **agility itself** — the combiner + config-selectable KEM — so HQC
drops in the moment a sound pure-Rust impl lands (as `ml-kem` did). Concretely:
1. **Build the KEM combiner + config-selectable KEM.** Agility is the deliverable; HQC is a future plug-in. Value stands even before HQC exists.
2. **Track `RustCrypto/KEMs`** for a pure-Rust HQC; adopt when it ships. Do **not** vendor the C-backed, RUSTSEC-flagged `pqcrypto-hqc`.
3. **Signatures already carry family diversity** (hash-based SLH-DSA ⊕ lattice) — the signature side is hedged *today*; only the KEM side waits.
4. Classic McEliece is not a near-term option either (also C-only in Rust; ~1 MB keys unfit for a per-connection handshake).

**Net:** the risk is real, the direction is right, and the mitigation is **gated on ecosystem maturity** — so we build the agility now and plug HQC when it is sound in pure Rust.
