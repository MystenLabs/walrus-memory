"""Compare independent read-only snapshots; no DB or network access."""
import json
import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('before')
parser.add_argument('after')
parser.add_argument('--expected-count', type=int)
args = parser.parse_args()
before = json.loads(Path(args.before).read_text())
after = json.loads(Path(args.after).read_text())
expected = args.expected_count if args.expected_count is not None else before['vector_count']
a = {row["id"]: row for row in before["rows"]}
b = {row["id"]: row for row in after["rows"]}
common = sorted(a.keys() & b.keys())
def parse_time(value):
    # Python3.9 accepts 3/6 fractional digits; PostgreSQL omits trailing zeros.
    normalized = value.replace("Z", "+00:00")
    normalized = re.sub(r"\.(\d+)(?=[+-]\d\d:\d\d$)",
        lambda match: "." + match[1].ljust(6, "0")[:6], normalized)
    return datetime.fromisoformat(normalized)
result = {
    "before_file": str(Path(args.before).resolve()),
    "after_file": str(Path(args.after).resolve()),
    "expected_count": expected,
    "run_id": after["run_id"],
    "before_count": before["vector_count"],
    "after_count": after["vector_count"],
    "missing_ids": sorted(a.keys() - b.keys()),
    "added_ids": sorted(b.keys() - a.keys()),
    "changed_stable_fields": [key for key in common if a[key]["stable_hash"] != b[key]["stable_hash"]],
    "regressed_updated_at": [key for key in common if parse_time(b[key]["updated_at"]) < parse_time(a[key]["updated_at"])],
    "changed_created_at": [key for key in common if a[key]["created_at"] != b[key]["created_at"]],
    "regressed_end_epoch": [key for key in common if b[key]["end_epoch"] < a[key]["end_epoch"]],
    "increased_end_epoch_count": sum(b[key]["end_epoch"] > a[key]["end_epoch"] for key in common),
    "unchanged_end_epoch_count": sum(b[key]["end_epoch"] == a[key]["end_epoch"] for key in common),
    "stable_fingerprint_equal": before["stable_fingerprint"] == after["stable_fingerprint"],
    "vector_total_count_unchanged": before.get('vector_total_count') == after.get('vector_total_count'),
}
result["all_passed"] = (
    before["run_id"] == after["run_id"]
    and expected > 0
    and before["catalog_count"] == after["catalog_count"] == len(a) == len(b) == expected
    and before["vector_count"] == after["vector_count"] == expected
    and result["increased_end_epoch_count"] == expected
    and result["stable_fingerprint_equal"]
    and result["vector_total_count_unchanged"]
    and not any(result[key] for key in (
        "missing_ids", "added_ids", "changed_stable_fields", "regressed_updated_at",
        "changed_created_at", "regressed_end_epoch"
    ))
)
print(json.dumps(result, indent=2))
sys.exit(0 if result["all_passed"] else 1)
