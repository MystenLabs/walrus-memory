"""Independently verify synthetic source/download files against a PG manifest."""
import hashlib
import argparse
import json
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('manifest')
parser.add_argument('scratch')
parser.add_argument('--expected-count', type=int)
parser.add_argument('--source-cipher-dir', help='Existing canonical ciphertext directory; indexed by origin_memory_id')
args = parser.parse_args()
manifest = json.loads(Path(args.manifest).read_text())
scratch = Path(args.scratch)
source_cipher_dir = Path(args.source_cipher_dir) if args.source_cipher_dir else scratch / 'ciphertext'
expected = args.expected_count if args.expected_count is not None else len(manifest)
failures = []
verified = 0
total_bytes = 0
def require(condition, message):
    if not condition:
        raise ValueError(message)

if expected <= 0 or len(manifest) != expected:
    failures.append({'error': 'Manifest count differs from expected cohort', 'expected': expected, 'observed': len(manifest)})
if [row.get('memory_id') for row in manifest] != list(range(expected)):
    failures.append({'error': 'Manifest does not contain ordered contiguous memory IDs'})
for row in manifest:
    memory_id = row["memory_id"]
    try:
        require(row["stage"] == "migrated", "catalog stage is not migrated")
        source_memory_id = row.get('origin_memory_id') if args.source_cipher_dir else memory_id
        if source_memory_id is None:
            source_memory_id = memory_id
        source = (source_cipher_dir / f"{source_memory_id}.bin").read_bytes()
        downloaded = (scratch / "downloads" / f"{memory_id}.bin").read_bytes()
        for label, data in (("source", source), ("download", downloaded)):
            require(len(data) == row["ciphertext_bytes"], f"{label} byte count differs")
            require(hashlib.sha256(data).hexdigest() == row["ciphertext_sha256"], f"{label} SHA-256 differs")
        require(downloaded == source, "downloaded bytes differ from seeded ciphertext")
        metadata = json.loads((scratch / "downloads" / f"{memory_id}.metadata.json").read_text())
        require(metadata["metadata"] == row["source_metadata"], "downloaded metadata map differs")
        obj = metadata["object"]
        require(obj.get("objectId") == row["source_object_id"], "downloaded source object ID differs")
        verified += 1
        total_bytes += len(downloaded)
    except (AssertionError, OSError, KeyError, ValueError) as error:
        failures.append({"memory_id": memory_id, "error": str(error)})

result = {
    "manifest_file": str(Path(args.manifest).resolve()),
    "scratch": str(scratch.resolve()),
    "source_cipher_dir": str(source_cipher_dir.resolve()),
    "expected_count": expected,
    "verified_source_and_download_count": verified,
    "verified_metadata_count": verified,
    "verified_download_bytes": total_bytes,
    "failures": failures,
    "all_passed": bool(manifest) and not failures and verified == expected,
    "scope": "saved_source_ciphertext_and_downloaded_ciphertext_and_source_metadata; new-chain metadata covered by runner reads",
}
print(json.dumps(result, indent=2))
sys.exit(0 if result["all_passed"] else 1)
