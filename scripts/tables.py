import csv
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
SIGNATURE_BYTES = 67 * 4 * 8


def rows(name):
    with (DATA / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def median(values):
    return statistics.median(float(v) for v in values)


def percentile(values, fraction):
    values = sorted(values)
    return values[min(len(values) - 1, int(fraction * len(values)))]


def bootstrap(values):
    values = [float(v) for v in values]
    rng = random.Random(0x504342 + len(values))
    medians = [statistics.median(rng.choices(values, k=len(values))) for _ in range(4000)]
    return percentile(medians, 0.025), percentile(medians, 0.975)


def describe(values):
    values = [float(v) for v in values]
    return statistics.median(values), min(values), max(values)


def cost_model():
    data = rows("cost_model/group_cost.csv")
    return {
        "occupancy": [int(r["occupancy"]) for r in data],
        "prove_s": [float(r["prove_ms"]) / 1000 for r in data],
        "peak_mib": [float(r["peak_mb"]) for r in data],
        "proof_kib": [float(r["proof_bytes"]) / 1024 for r in data],
        "verify_ms": [float(r["verify_ms"]) for r in data],
        "accumulation_step_s": float(data[0]["agg_step_ms"]) / 1000,
    }


def query_cost():
    out = {}
    for r in rows("query_cost/fri_query_cost.csv"):
        out[int(r["query_rounds"])] = {
            "group_proof_kib": float(r["group_proof_bytes"]) / 1024,
            "chain_proof_kib": float(r["chain_proof_bytes"]) / 1024,
            "chain_verify_ms": float(r["chain_verify_ms"]),
            "accumulation_over_group": float(r["block_step_ms"]) / float(r["group_prove_ms"]),
            "chain_margin_unique_bits": float(r["chain_margin_unique_bits"]),
            "break_even": math.ceil(int(r["chain_proof_bytes"]) / SIGNATURE_BYTES),
        }
    return out


def chain():
    data = rows("chain/pcc_chain_scaling.csv")
    later = data[1:]
    shares = [100 * float(r["group_prove_ms"]) / (float(r["group_prove_ms"]) + float(r["block_step_ms"])
                                                 + float(r["chain_step_ms"])) for r in later]
    return {
        "blocks": int(data[-1]["blocks"]),
        "transactions": int(data[-1]["txs_total"]),
        "proof_bytes": int(data[-1]["chain_proof_bytes"]),
        "proof_sizes": len({r["chain_proof_bytes"] for r in data}),
        "verify_ms": describe(r["chain_verify_ms"] for r in data),
        "accumulation_s": median(r["block_step_ms"] for r in later) / 1000,
        "chain_step_s": median(r["chain_step_ms"] for r in data) / 1000,
        "group_share_pct": statistics.median(shares),
    }


def adversarial():
    cases = [(r["attack"], r["api outcome"].strip(), r["circuit outcome"].strip())
             for r in rows("adversarial/pcc_adversarial.csv")]
    cases += [(r["blocks"], r["group_prove_ms"].strip(), r["group_proof_bytes"].strip())
              for r in rows("xmss/pcc_xmss.csv") if r["mode"] == "ADV"]
    attacks = [c for c in cases if not (c[0].lower().startswith("honest") or "control" in c[0].lower())]
    return {
        "cases": len(cases),
        "controls": len(cases) - len(attacks),
        "attacks": len(attacks),
        "accepted": sum("ACCEPTED" in (api.upper(), circuit.upper()) for _, api, circuit in attacks),
    }


def scaling():
    groups = defaultdict(list)
    for r in rows("distributed/dist_summary.csv"):
        if r["tag"].startswith("scale-"):
            groups[(int(r["k"]), int(r["workers"]))].append(r)
    out = {}
    for (k, w), runs in sorted(groups.items()):
        out[(k, w)] = {"prove_s": median(r["prove_phase_ms"] for r in runs) / 1000,
                       "total_s": median(r["total_ms"] for r in runs) / 1000}
    one = out[(32, 1)]
    eight = out[(32, 8)]
    return {
        "cells": out,
        "group_speedup": one["prove_s"] / eight["prove_s"],
        "block_speedup": one["total_s"] / eight["total_s"],
        "accumulation_share_pct": statistics.median(
            100 * float(r["agg_ms"]) / float(r["total_ms"]) for r in groups[(32, 8)]),
        "group_share_one_pct": 100 * one["prove_s"] / one["total_s"],
        "ceiling": one["total_s"] / (one["total_s"] - one["prove_s"]),
    }


def faults():
    groups = defaultdict(list)
    for r in rows("distributed/dist_summary.csv"):
        if r["tag"].startswith("fault-"):
            groups[r["tag"].removeprefix("fault-")].append(r)
    return {name: {"runs": len(runs), "valid": sum(r["final_proof_valid"] == "true" for r in runs),
                   "total_s": median(r["total_ms"] for r in runs) / 1000}
            for name, runs in sorted(groups.items())}


def aggregation():
    groups = defaultdict(list)
    for r in rows("aggregation/aggregation_summary.csv"):
        groups[(int(r["k"]), int(r["workers"]), int(r["block_fan_in"]))].append(r)
    return {key: {"total_s": median(r["total_ms"] for r in runs) / 1000,
                  "accumulation_s": median(r["agg_ms"] for r in runs) / 1000,
                  "depth": int(runs[0]["aggregation_depth"]),
                  "coordinator_peak_mib": median(r["coord_peak_mb"] for r in runs)}
            for key, runs in sorted(groups.items())}


def budget():
    data = rows("budget/trials.csv")
    trial = {(int(r["k"]), int(r["rep"]), int(r["g"])): r for r in data}
    out = {}
    for k in (16, 32):
        for g in (2, 4, 8):
            runs = [r for r in data if (int(r["k"]), int(r["g"])) == (k, g)]
            online = [float(r["online_ms"]) / 1000 for r in runs]
            out[(k, g)] = {
                "online_s": describe(online),
                "group_s": median(r["prove_phase_ms"] for r in runs) / 1000,
                "accumulation_s": median(r["agg_ms"] for r in runs) / 1000,
                "chain_s": median(float(r["chain_prove_ms"]) + float(r["chain_verify_ms"]) for r in runs) / 1000,
                "cold_s": describe(float(r["cold_ms"]) / 1000 for r in runs),
                "scope_peak_gib": max(float(r["scope_memory_peak_bytes"]) for r in runs) / 1024 ** 3,
                "speedup_over_g4": statistics.median(
                    float(trial[(k, int(r["rep"]), 4)]["online_ms"]) / float(r["online_ms"]) for r in runs),
                "online_without_pause_s": statistics.median(
                    float(r["online_ms"]) / 1000 for r in runs if not (k == 32 and int(r["rep"]) == 2)),
            }
    return out


def commitment_hashing():
    out = {}
    for g in (2, 4, 8):
        data = rows(f"commitment_hashing/binding_g{g}.csv")
        pairs = defaultdict(dict)
        for r in data:
            pairs[int(r["rep"])][r["bind"]] = r
        plain, digest = (next(r for r in data if r["bind"] == bind) for bind in ("false", "true"))
        out[g] = {
            "plain_gates": int(plain["gates"]),
            "digest_gates": int(digest["gates"]),
            "degrees": (int(plain["degree"]), int(digest["degree"])),
            "proof_bytes": (int(plain["proof_bytes"]), int(digest["proof_bytes"])),
            "digest_over_plain": describe(float(p["true"]["prove_ms"]) / float(p["false"]["prove_ms"])
                                          for p in pairs.values()),
        }
    return out


def persistent():
    data = rows("persistent/blocks.csv")
    reps = sorted({int(r["rep"]) for r in data})

    def total(policy, rep, field="total_ms"):
        return sum(float(r[field]) for r in data if r["policy"] == policy and int(r["rep"]) == rep) / 1000

    out = {}
    for policy in ("static", "ewma", "periodic"):
        out[policy] = {
            "total_s": statistics.median(total(policy, rep) for rep in reps),
            "static_over_policy": describe(total("static", rep) / total(policy, rep) for rep in reps),
            "calibration_s": statistics.median(total(policy, rep, "calibration_ms") for rep in reps),
            "worker0_groups": [sorted({int(r["worker0_groups"]) for r in data
                                       if r["policy"] == policy and int(r["block"]) == block})
                               for block in range(1, 13)],
        }
    return out


def two_host():
    out = {}
    for k, name in ((20, "k20"), (64, "k64")):
        by_tag = defaultdict(dict)
        for r in rows(f"two_host/summary_{name}.csv"):
            by_tag[r["tag"]][r["rep"]] = r
        server, resource, maxfit = (by_tag[t] for t in
                                    ("twonode-server-w4", "twonode-resource-r4-l4", "twonode-maxfit-r4-l4"))
        reps = sorted(resource)

        def ratio(a, b):
            values = [float(a[rep]["total_ms"]) / float(b[rep]["total_ms"]) for rep in reps]
            return (statistics.median(values), *bootstrap(values))

        out[k] = {
            "total_s": {label: median(r["total_ms"] for r in runs.values()) / 1000
                        for label, runs in (("server", server), ("resource", resource), ("maxfit", maxfit))},
            "maxfit_over_resource": ratio(maxfit, resource),
            "resource_over_server": ratio(resource, server),
        }
    return out


def replay():
    groups = defaultdict(list)
    for r in rows("replay/replay.csv"):
        groups[int(r["transactions"])].append(r)
    return {t: {"named_ms": median(r["named_ms"] for r in runs),
                "serial_ms": median(r["serial_ms"] for r in runs),
                "parallel_ms": median(r["parallel_ms"] for r in runs),
                "parallel_over_named": describe(float(r["parallel_ms"]) / float(r["named_ms"]) for r in runs)}
            for t, runs in sorted(groups.items())}


def pipeline():
    pcb = rows("external/pcb_trials.csv")
    blocks = rows("external/pcb_blocks.csv")
    lean = rows("external/leanvm_trials.csv")
    out = {}
    for k in (8, 16):
        p = [r for r in pcb if int(r["k"]) == k]
        b = [r for r in blocks if int(r["k"]) == k]
        v = [r for r in lean if int(r["k"]) == k]
        out[k] = {
            "pcb_block_s": describe(float(r["block_ms"]) / 1000 for r in p),
            "pcb_chain_s": describe(float(r["online_ms"]) / 1000 for r in p),
            "leanvm_s": describe(float(r["online_ms"]) / 1000 for r in v),
            "pcb_block_proof_kib": median(r["block_proof_bytes"] for r in b) / 1024,
            "pcb_chain_proof_kib": median(r["chain_proof_bytes"] for r in p) / 1024,
            "leanvm_proof_kib": median(r["proof_bytes_with_keys"] for r in v) / 1024,
            "pcb_block_check_ms": median(r["block_verify_ms"] for r in b),
            "pcb_chain_check_ms": median(r["chain_verify_ms"] for r in p),
            "leanvm_check_ms": median(r["verify_ms"] for r in v),
        }
    return out


def wide_area():
    data = rows("wide_area/pcb_trials.csv")
    control = {(int(r["k"]), int(r["rep"])): r for r in data if "-sse-only-" in r["tag"]}
    out = {}
    for k in (8, 16, 32):
        for label in ("wan-maxfit", "wan-eft", "wan-resource"):
            runs = [r for r in data if int(r["k"]) == k and f"-{label}-h" in r["tag"]]
            out[(k, label)] = describe(float(control[(k, int(r["rep"]))]["online_ms"]) / float(r["online_ms"])
                                       for r in runs)
    return out


def same_host():
    groups = defaultdict(list)
    for r in rows("external/same_host_runs.csv"):
        groups[(r["system"], int(r["n"]))].append(float(r["prover_ms"]))
    return {key: statistics.median(values) / 1000 for key, values in sorted(groups.items())}


def scheduling():
    data = rows("scheduling/sched_ablation.csv")
    base = {(r["fleet"], r["workers"], r["mem_mb"], r["k"]): float(r["objective"])
            for r in data if r["ablation"] == "full" and r["feasible"] == "true"}
    deltas, infeasible = defaultdict(list), defaultdict(int)
    for r in data:
        key = (r["fleet"], r["workers"], r["mem_mb"], r["k"])
        if r["ablation"] == "full" or key not in base:
            continue
        if r["feasible"] == "true":
            deltas[r["ablation"]].append(100 * (float(r["objective"]) - base[key]) / base[key])
        else:
            infeasible[r["ablation"]] += 1
    gaps = rows("scheduling/sched_optgap.csv")
    closed = [float(r["proved_gap_pct"]) for r in gaps if r["exact_proved_optimal"] == "true"]
    return {
        "ablation": {name: {"median": statistics.median(v), "p90": percentile(v, 0.9), "max": max(v),
                            "infeasible": infeasible[name]} for name, v in sorted(deltas.items())},
        "instances": len(gaps),
        "closed": len(closed),
        "exact": sum(g < 1e-6 for g in closed),
        "median_gap_pct": statistics.median(closed),
        "max_gap_pct": max(closed),
    }


def archival():
    data = rows("chain/pcc_chain_scaling.csv")
    proof = int(data[-1]["chain_proof_bytes"])
    blocks = int(data[-1]["blocks"])
    groups = blocks * int(data[-1]["groups_per_block"])
    transactions = int(data[-1]["txs_total"])
    common = 8 + 56 * blocks + 8 * groups + 72 * transactions
    return {
        "break_even": math.ceil(proof / SIGNATURE_BYTES),
        "signature_saving_pct": 100 * (1 - proof / (SIGNATURE_BYTES * transactions)),
        "common_bytes": common,
        "total_saving_pct": 100 * (1 - (common + proof) / (common + SIGNATURE_BYTES * transactions)),
    }


SECTIONS = {
    "cost_model": cost_model, "query_cost": query_cost, "chain": chain, "adversarial": adversarial,
    "scaling": scaling, "faults": faults, "aggregation": aggregation, "budget": budget,
    "commitment_hashing": commitment_hashing, "persistent": persistent,
    "two_host": two_host, "replay": replay, "pipeline": pipeline, "wide_area": wide_area,
    "same_host": same_host, "scheduling": scheduling, "archival": archival,
}


def show(value, indent=2):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict):
                print(" " * indent + str(key))
                show(item, indent + 2)
            else:
                print(" " * indent + f"{key}: {fmt(item)}")
    else:
        print(" " * indent + fmt(value))


def fmt(value):
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(fmt(v) for v in value) + "]"
    return str(value)


def main():
    names = sys.argv[1:] or list(SECTIONS)
    for name in names:
        print(name)
        show(SECTIONS[name]())


if __name__ == "__main__":
    main()
