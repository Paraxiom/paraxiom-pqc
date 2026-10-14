# NIST ACVP vectors (subsets)

`tests/acvp.rs` runs these known-answer vectors. Each JSON file here is a subset of one file
from the NIST ACVP-Server repository, taken at commit
[`975de31eb83d87039ec88934fdc47d8c312b892d`](https://github.com/usnistgov/ACVP-Server/commit/975de31eb83d87039ec88934fdc47d8c312b892d)
("RELEASE/v1.1.0.43 including hotfix patches", 2026-08-12). The files were downloaded without
credentials from `raw.githubusercontent.com`.

| File here | Source in usnistgov/ACVP-Server | SHA-256 of the source file |
|---|---|---|
| `ML-KEM-keyGen-FIPS203.json` | `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| `ML-KEM-encapDecap-FIPS203.json` | `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |
| `ML-DSA-keyGen-FIPS204.json` | `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json` | `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` |
| `ML-DSA-sigGen-FIPS204.json` | `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json` | `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22` |
| `ML-DSA-sigVer-FIPS204.json` | `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json` | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` |
| `SLH-DSA-keyGen-FIPS205.json` | `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json` | `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920` |
| `SLH-DSA-sigGen-FIPS205.json` | `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json` | `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba` |
| `SLH-DSA-sigVer-FIPS205.json` | `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` |

The internal projection holds the inputs and the expected results of each test case. The
subsets keep the ACVP layout and field names, and every value kept is copied unchanged.
`extract.py` produced them from the downloaded files:

```sh
python3 tests/acvp/extract.py <directory holding the eight downloaded json-files directories>
```

## What was kept

Only what this crate's API can use: the external, pure interface (no HashML-DSA or
HashSLH-DSA, no `internal` interface, no external mu) and, for SLH-DSA, the two parameter sets
the crate offers (SHAKE-128f and SHAKE-256s).

| File | Groups kept | Test cases kept |
|---|---|---|
| ML-KEM keyGen | 512, 768, 1024 | first 10 per set (30) |
| ML-KEM encapDecap | encapsulation, decapsulation, encapsulationKeyCheck | encapsulation: first 10 per set; decapsulation (valid and modified ciphertexts) and encapsulation-key checks: all (90 in total) |
| ML-DSA keyGen | 44, 65, 87 | first 10 per set (30) |
| ML-DSA sigGen | external, pure, deterministic and hedged | per group: empty context, 255-byte context, then the shortest messages, up to 6 (deterministic) or 4 (hedged) (30) |
| ML-DSA sigVer | external, pure | per group, the shortest-message case of each reason, plus empty contexts (18) |
| SLH-DSA keyGen | SHAKE-128f, SHAKE-256s | all (20) |
| SLH-DSA sigGen | SHAKE-128f, SHAKE-256s; external, pure, deterministic | empty context, 255-byte context, shortest message (6) |
| SLH-DSA sigVer | SHAKE-128f, SHAKE-256s; external, pure | per group, the shortest-message case of each reason, plus empty contexts (14) |

Dropped: ML-KEM `decapsulationKeyCheck` (expanded decapsulation keys only; this crate stores
the 64-byte seed), and the per-test fields the tests do not read (`deferred`, `hashAlg`, and the
ML-KEM `dk` of encapsulation cases, for example).

## What the tests check

- ML-KEM: the 64-byte `d || z` seed that `kem::DecapsulationKey` stores rebuilds NIST's ek and
  expanded dk; a NIST key pair round-trips through `kem::encapsulate` / `kem::decapsulate`, and a
  modified ciphertext decapsulates to `J(z || c)`; deterministic encapsulation gives NIST's c and
  K; the backend decapsulates NIST's valid and modified ciphertexts to NIST's K; and
  `kem::encapsulate` accepts exactly the encapsulation keys that pass NIST's modulus check.
- ML-DSA: `SigningKey::from_seed` and `KeyGen::from_seed` rebuild NIST's sk and pk; NIST seeds
  sign and verify through `sign::sign` and `sign::sign_deterministic_dangerous`; the 814-round
  kernel and upstream's deterministic loop both return NIST's deterministic signatures; hedged
  signing returns NIST's signature when given NIST's `rnd`; verification accepts exactly NIST's
  valid signatures, through `sign::verify` where the context is empty.
- SLH-DSA: key generation rebuilds NIST's sk and pk (pk is the second half of sk, as
  `sign::keypair` assumes); `sign::sign` returns NIST's signature byte for byte where the context
  is empty; verification accepts exactly NIST's valid signatures (modified R, FORS, hypertree,
  message, and signatures one byte too long or too short are refused).

The SHAKE-256s signing vectors are `#[ignore]`d in debug builds; run them with
`cargo test --release --test acvp -- --ignored`.

Falcon (FIPS 206) has no ACVP vectors yet; `tests/falcon_verify.rs` holds a fixed vector made
with falcon-rs.
