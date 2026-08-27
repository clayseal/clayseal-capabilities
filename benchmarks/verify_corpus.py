"""Verify the fetched corpora match the manifest the published results were run on.

    python -m benchmarks.verify_corpus            # check
    python -m benchmarks.verify_corpus --update   # re-pin after an intentional bump

External corpora are fetched from upstream repositories that keep moving. A
result quoted against "RedCode" is not reproducible unless it says *which*
RedCode, so every run is pinned to a content hash of the data it read. Without
this, a number that fails to reproduce is indistinguishable from a number that
was wrong, and the first is a corpus bump while the second is a retraction.

The hash covers file paths and contents, excluding `.git`, so a sparse checkout
that pulls new commits without changing the dataset still verifies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / ".benchmark-corpus"
MANIFEST = ROOT / "benchmarks" / "corpus_manifest.json"


def digest(directory: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    files = sorted(
        f for f in directory.rglob("*")
        if f.is_file() and ".git/" not in str(f)
    )
    for f in files:
        h.update(str(f.relative_to(CORPUS)).encode())
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest(), len(files)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify benchmark corpus pinning")
    p.add_argument("--update", action="store_true", help="re-pin the manifest to what is on disk")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    if not CORPUS.exists():
        print(f"corpus not fetched: run benchmarks/fetch_corpora.sh", file=sys.stderr)
        return 2

    current = {}
    for sub in sorted(d for d in CORPUS.iterdir() if d.is_dir()):
        sha, count = digest(sub)
        current[sub.name] = {"sha256": sha, "files": count}

    if args.update:
        MANIFEST.write_text(json.dumps(current, indent=2) + "\n")
        print(f"pinned {len(current)} corpora to {MANIFEST}")
        return 0

    if not MANIFEST.exists():
        print(f"no manifest at {MANIFEST}; run with --update", file=sys.stderr)
        return 2

    expected = json.loads(MANIFEST.read_text())
    problems = []
    for name, want in expected.items():
        got = current.get(name)
        if got is None:
            problems.append(f"{name}: missing (expected {want['files']} files)")
        elif got["sha256"] != want["sha256"]:
            problems.append(
                f"{name}: hash mismatch, expected {want['sha256'][:12]} "
                f"({want['files']} files), got {got['sha256'][:12]} ({got['files']} files)"
            )
    for name in current:
        if name not in expected:
            problems.append(f"{name}: present but not pinned")

    if problems:
        print("corpus does not match the manifest:\n  " + "\n  ".join(problems), file=sys.stderr)
        print("\nPublished results were measured on the pinned contents. Either restore them "
              "or re-pin with --update and re-run every affected benchmark.", file=sys.stderr)
        return 1

    print(f"corpus verified: {len(expected)} datasets match the manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
