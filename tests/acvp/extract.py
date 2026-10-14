#!/usr/bin/env python3
"""Cut the NIST ACVP vector subsets in this directory out of the ACVP-Server files.

Usage: python3 extract.py <dir holding the downloaded ACVP-Server json-files directories>

The input is gen-val/json-files/<name>/internalProjection.json from
https://github.com/usnistgov/ACVP-Server at commit COMMIT below. The output keeps the ACVP
layout (testGroups -> tests) and the ACVP field names; it only drops groups, test cases and
fields that tests/acvp.rs does not use. Every value that is kept is copied unchanged.
Selection rules are in the functions below and in README.md.
"""

import hashlib
import json
import os
import sys

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCE = "https://github.com/usnistgov/ACVP-Server/blob/{commit}/gen-val/json-files/{name}/internalProjection.json"
OUR_SLH_SETS = ("SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-256s")


def keep(test, fields):
    return {f: test[f] for f in fields if f in test}


def first(tests, n):
    return sorted(tests, key=lambda t: t["tcId"])[:n]


def by_message_length(tests):
    return sorted(tests, key=lambda t: (len(t["message"]), t["tcId"]))


def boundary_then_shortest(tests, n):
    """Empty context, 255-byte context, then the shortest messages, up to n tests."""
    chosen = [t for t in tests if len(t["context"]) == 0]
    chosen += [t for t in tests if len(t["context"]) == 2 * 255 and t not in chosen]
    for t in by_message_length(tests):
        if len(chosen) >= n:
            break
        if t not in chosen:
            chosen.append(t)
    return sorted(chosen[:max(n, len(chosen))], key=lambda t: t["tcId"])


def one_per_reason(tests):
    """For each failure reason, the test with the shortest message; plus empty contexts."""
    chosen = []
    seen = set()
    for t in by_message_length(tests):
        if t["reason"] not in seen:
            seen.add(t["reason"])
            chosen.append(t)
    chosen += [t for t in tests if len(t["context"]) == 0 and t not in chosen]
    return sorted(chosen, key=lambda t: t["tcId"])


def ml_kem_keygen(group):
    return [keep(t, ("tcId", "d", "z", "ek", "dk")) for t in first(group["tests"], 10)]


def ml_kem_encap_decap(group):
    f = group["function"]
    if f == "encapsulation":
        return [keep(t, ("tcId", "ek", "m", "c", "k")) for t in first(group["tests"], 10)]
    if f == "decapsulation":
        return [keep(t, ("tcId", "dk", "c", "k", "reason")) for t in group["tests"]]
    if f == "encapsulationKeyCheck":
        return [keep(t, ("tcId", "ek", "testPassed", "reason")) for t in group["tests"]]
    return None  # decapsulationKeyCheck: expanded keys only, which this crate does not take


def ml_dsa_keygen(group):
    return [keep(t, ("tcId", "seed", "pk", "sk")) for t in first(group["tests"], 10)]


def ml_dsa_siggen(group):
    if (group["signatureInterface"], group["preHash"], group["externalMu"]) != ("external", "pure", False):
        return None
    n = 6 if group["deterministic"] else 4
    fields = ("tcId", "pk", "sk", "message", "context", "rnd", "signature")
    return [keep(t, fields) for t in boundary_then_shortest(group["tests"], n)]


def ml_dsa_sigver(group):
    if (group["signatureInterface"], group["preHash"], group["externalMu"]) != ("external", "pure", False):
        return None
    fields = ("tcId", "pk", "message", "context", "signature", "testPassed", "reason")
    return [keep(t, fields) for t in one_per_reason(group["tests"])]


def slh_dsa_keygen(group):
    if group["parameterSet"] not in OUR_SLH_SETS:
        return None
    return [keep(t, ("tcId", "skSeed", "skPrf", "pkSeed", "sk", "pk")) for t in group["tests"]]


def slh_dsa_siggen(group):
    if group["parameterSet"] not in OUR_SLH_SETS:
        return None
    if (group["signatureInterface"], group["preHash"], group["deterministic"]) != ("external", "pure", True):
        return None
    fields = ("tcId", "pk", "sk", "message", "context", "signature")
    return [keep(t, fields) for t in boundary_then_shortest(group["tests"], 3)]


def slh_dsa_sigver(group):
    if group["parameterSet"] not in OUR_SLH_SETS:
        return None
    if (group["signatureInterface"], group["preHash"]) != ("external", "pure"):
        return None
    fields = ("tcId", "pk", "message", "context", "signature", "testPassed", "reason")
    return [keep(t, fields) for t in one_per_reason(group["tests"])]


FILES = {
    "ML-KEM-keyGen-FIPS203": ml_kem_keygen,
    "ML-KEM-encapDecap-FIPS203": ml_kem_encap_decap,
    "ML-DSA-keyGen-FIPS204": ml_dsa_keygen,
    "ML-DSA-sigGen-FIPS204": ml_dsa_siggen,
    "ML-DSA-sigVer-FIPS204": ml_dsa_sigver,
    "SLH-DSA-keyGen-FIPS205": slh_dsa_keygen,
    "SLH-DSA-sigGen-FIPS205": slh_dsa_siggen,
    "SLH-DSA-sigVer-FIPS205": slh_dsa_sigver,
}


def main(src_root):
    here = os.path.dirname(os.path.abspath(__file__))
    for name, select in FILES.items():
        path = os.path.join(src_root, name, "internalProjection.json")
        raw = open(path, "rb").read()
        data = json.loads(raw)
        groups = []
        for g in data["testGroups"]:
            tests = select(g)
            if tests:
                meta = {k: v for k, v in g.items() if k != "tests"}
                groups.append({**meta, "tests": tests})
        out = {
            "source": SOURCE.format(commit=COMMIT, name=name),
            "sourceSha256": hashlib.sha256(raw).hexdigest(),
            "note": "Subset of the ACVP internal projection; values copied unchanged. See README.md.",
            **{k: v for k, v in data.items() if k != "testGroups"},
            "testGroups": groups,
        }
        with open(os.path.join(here, name + ".json"), "w") as f:
            json.dump(out, f, indent=1)
            f.write("\n")
        count = sum(len(g["tests"]) for g in groups)
        print(f"{name}: {len(groups)} groups, {count} tests")


if __name__ == "__main__":
    main(sys.argv[1])
