#!/usr/bin/env python3
"""Fault-segment extractor -- entry point.

Usage:
    python3 main.py INPUT_JSON OUTPUT_JSON

Behaviour:
  * success: the output JSON array atomically replaces OUTPUT_JSON,
    exit code 0;
  * invalid input (structure / types / duplicates / unknown members):
    the whole input is rejected, one error JSON path (zero-based
    indices; "$" for JSON syntax errors) is printed to stderr, the old
    OUTPUT_JSON is kept untouched, exit code 1;
  * I/O problems (unreadable input, unwritable output): exit code 2.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from faultseg.errors import InputError
from faultseg.pipeline import run_text


def main(argv):
    if len(argv) != 3:
        print("usage: main.py INPUT_JSON OUTPUT_JSON", file=sys.stderr)
        return 2
    in_path, out_path = argv[1], argv[2]

    try:
        with open(in_path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print("cannot read input: %s" % exc, file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print("$", file=sys.stderr)
        return 1

    try:
        result = run_text(text)
    except InputError as exc:
        print(exc.path, file=sys.stderr)
        return 1

    # Atomic replace so a failed run never leaves a half-written file.
    out_dir = os.path.dirname(os.path.abspath(out_path))
    try:
        fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".faultseg-", suffix=".tmp")
    except OSError as exc:
        print("cannot write output: %s" % exc, file=sys.stderr)
        return 2
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=True, separators=(",", ":"))
            fh.write("\n")
        os.replace(tmp, out_path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        print("cannot write output: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
