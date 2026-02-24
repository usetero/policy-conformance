#!/usr/bin/env python3
"""Convert base64-encoded traceId/spanId/parentSpanId to hex in JSON test files."""

import base64
import json
import glob
import sys
import os

FIELDS = {"traceId", "spanId", "parentSpanId"}


def is_base64(s: str) -> bool:
    """Check if string looks like base64 (has padding or base64 chars only)."""
    if not s:
        return False
    # Already hex? (only hex chars, correct length)
    if all(c in "0123456789abcdef" for c in s) and len(s) in (16, 32):
        return False
    try:
        base64.b64decode(s)
        return True
    except Exception:
        return False


def b64_to_hex(s: str) -> str:
    """Convert base64 string to lowercase hex."""
    if not s or not is_base64(s):
        return s
    raw = base64.b64decode(s)
    return raw.hex()


def convert_obj(obj):
    """Recursively convert base64 fields to hex in a JSON object."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in FIELDS and isinstance(value, str) and value:
                obj[key] = b64_to_hex(value)
            else:
                convert_obj(value)
    elif isinstance(obj, list):
        for item in obj:
            convert_obj(item)


def process_file(path: str, dry_run: bool = False) -> bool:
    """Process a single JSON file. Returns True if changes were made."""
    with open(path, "r") as f:
        content = f.read()

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return False

    original = json.dumps(data)
    convert_obj(data)
    converted = json.dumps(data)

    if original == converted:
        return False

    if not dry_run:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    return True


def main():
    dry_run = "--dry-run" in sys.argv

    patterns = [
        "testcases/*/input.json",
        "testcases/*/expected.json",
        "testcases/*/input_*.json",
        "testcases/*/expected_*.json",
    ]

    changed = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if process_file(path, dry_run):
                changed.append(path)

    if dry_run:
        print(f"Would modify {len(changed)} files:")
    else:
        print(f"Modified {len(changed)} files:")

    for path in changed:
        print(f"  {path}")


if __name__ == "__main__":
    main()
