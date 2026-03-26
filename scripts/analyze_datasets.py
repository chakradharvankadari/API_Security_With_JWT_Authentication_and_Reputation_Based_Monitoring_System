from __future__ import annotations

import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUT_FILE = PROJECT_ROOT / "data" / "dataset_profile.json"


def _safe_float(value: str) -> bool:
    try:
        float(value)
        return True
    except Exception:
        return False


def profile_csv(path: Path, numeric_checks: list[str] | None = None) -> dict:
    numeric_checks = numeric_checks or []
    row_count = 0
    non_numeric = {name: 0 for name in numeric_checks}
    empty_counts: dict[str, int] = {}

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        for col in columns:
            empty_counts[col] = 0

        for row in reader:
            row_count += 1
            for col in columns:
                val = (row.get(col) or "").strip()
                if val == "":
                    empty_counts[col] += 1
            for name in numeric_checks:
                if name in row:
                    val = (row.get(name) or "").strip()
                    if val and not _safe_float(val):
                        non_numeric[name] += 1

    top_empty = sorted(empty_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {
        "file": str(path.name),
        "rows": row_count,
        "columns": len(columns),
        "column_names": columns,
        "non_numeric_counts": non_numeric,
        "top_empty_columns": [{"column": k, "empty_rows": v} for k, v in top_empty if v > 0],
    }


def main() -> None:
    files = {
        "attack_patterns.csv": [],
        "api_access_behaviour_anomaly.csv": [],
        "network_traffic_flows.csv": ["pktTotalCount", "octetTotalCount", "flowDuration", "std_dev_ps"],
        "reputation_seed.csv": [],
    }

    results = []
    for name, checks in files.items():
        file_path = RAW_DIR / name
        if not file_path.exists():
            results.append({"file": name, "error": "missing"})
            continue
        results.append(profile_csv(file_path, checks))

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps({"profiles": results}, indent=2), encoding="utf-8")
    print(f"Wrote dataset profile: {OUT_FILE}")


if __name__ == "__main__":
    main()
