#!/usr/bin/env python3
import csv
import statistics
import sys

def finite_number(row, field, path):
    value = float(row[field])
    if not (value >= 0.0 and value < float("inf")):
        raise ValueError(f"invalid {field} in {path}")
    return value

def quartile_span(values):
    values = sorted(values)
    if len(values) < 4:
        return 0.0
    return values[3 * len(values) // 4] - values[len(values) // 4]

def main():
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: merge_group_profiles.py OUTPUT INPUT1 [INPUT...] "
            "[--aggregation-profile FILE]"
        )
    output = sys.argv[1]
    args = sys.argv[2:]
    aggregation_path = None
    if "--aggregation-profile" in args:
        index = args.index("--aggregation-profile")
        try:
            aggregation_path = args[index + 1]
        except IndexError as error:
            raise ValueError("--aggregation-profile requires a path") from error
        del args[index:index + 2]
    paths = args
    if not paths:
        raise ValueError("at least one worker profile is required")
    inputs = []
    for path in paths:
        with open(path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if not rows:
            raise ValueError(f"empty profile {path}")
        for row in rows:
            for field in (
                "prove_ms", "peak_mb", "proof_bytes", "verify_ms", "agg_step_ms",
                "agg_peak_mb", "build_ms",
            ):
                finite_number(row, field, path)
        inputs.append(rows)

    aggregation = None
    if aggregation_path:
        with open(aggregation_path, newline="", encoding="utf-8") as handle:
            aggregation_rows = list(csv.DictReader(handle))
        if not aggregation_rows:
            raise ValueError(f"empty aggregation profile {aggregation_path}")
        aggregation = aggregation_rows[-1]

    budgets = {row["circuit_budget"] for rows in inputs for row in rows}
    circuit_ids = {row["circuit_id"] for rows in inputs for row in rows}
    if len(budgets) != 1 or len(circuit_ids) != 1:
        raise ValueError("profiles do not describe one fixed group circuit")
    if aggregation is not None:
        if aggregation["circuit_budget"] not in budgets or aggregation["circuit_id"] not in circuit_ids:
            raise ValueError("aggregation profile describes a different group circuit")
        if aggregation["occupancy"] != aggregation["circuit_budget"]:
            raise ValueError("aggregation profile must use the full circuit occupancy")
        finite_number(aggregation, "agg_step_ms", aggregation_path)
        finite_number(aggregation, "agg_peak_mb", aggregation_path)
    expected = {row["occupancy"] for row in inputs[0]}
    for rows in inputs:
        if {row["occupancy"] for row in rows} != expected:
            raise ValueError("profiles measure different occupancy sets")

    fields = [
        "circuit_budget",
        "occupancy",
        "circuit_id",
        "prove_ms",
        "peak_mb",
        "proof_bytes",
        "verify_ms",
        "agg_step_ms",
        "agg_peak_mb",
        "build_ms",
        "prove_iqr_ms",
        "verify_iqr_ms",
        "reps",
        "worker_processes",
    ]
    merged = []
    for occupancy in sorted(expected, key=int):
        rows = [next(row for row in group if row["occupancy"] == occupancy) for group in inputs]
        proof_sizes = {row["proof_bytes"] for row in rows}
        if len(proof_sizes) != 1:
            raise ValueError(f"proof size differs at occupancy {occupancy}")
        prove = [float(row["prove_ms"]) for row in rows]
        verify = [float(row["verify_ms"]) for row in rows]
        merged.append(
            {
                "circuit_budget": rows[0]["circuit_budget"],
                "occupancy": occupancy,
                "circuit_id": rows[0]["circuit_id"],
                "prove_ms": f"{statistics.median(prove):.1f}",
                "peak_mb": f"{max(float(row['peak_mb']) for row in rows):.0f}",
                "proof_bytes": rows[0]["proof_bytes"],
                "verify_ms": f"{statistics.median(verify):.3f}",
                "agg_step_ms": (
                    aggregation["agg_step_ms"] if aggregation
                    else f"{statistics.median(float(row['agg_step_ms']) for row in rows):.1f}"
                ),
                "agg_peak_mb": (
                    aggregation["agg_peak_mb"] if aggregation
                    else f"{max(float(row['agg_peak_mb']) for row in rows):.0f}"
                ),
                "build_ms": f"{statistics.median(float(row['build_ms']) for row in rows):.0f}",
                "prove_iqr_ms": f"{quartile_span(prove):.1f}",
                "verify_iqr_ms": f"{quartile_span(verify):.3f}",
                "reps": str(sum(int(row["reps"]) for row in rows)),
                "worker_processes": str(len(rows)),
            }
        )

    with open(output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(merged)

if __name__ == "__main__":
    main()
