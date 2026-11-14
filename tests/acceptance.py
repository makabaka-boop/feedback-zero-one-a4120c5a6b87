#!/usr/bin/env python3
"""Independent enumeration acceptance tests.

Usage: python3 tests/acceptance.py [NUM_RANDOM] [SEED]

Layers:
  1. directed valid cases (incl. the spec example) checked against
     hand-computed outputs, both in-process and through the CLI;
  2. directed invalid cases checked for exit code, exact error JSON
     path on stderr, and preservation of the old output file;
  3. randomized differential testing: the engine is compared against
     the independent brute-force enumerator in tests/brute_force.py,
     plus structural invariants of every published batch;
  4. fuzzing with mutated/random documents: either a clean rejection
     with a "$"-rooted path, or (if valid) agreement with brute force;
  5. file behaviour: success replaces the output, failure keeps it;
  6. a moderate-size smoke run.
"""

import copy
import json
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _p in (ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from faultseg.errors import InputError
from faultseg.pipeline import run_text
from faultseg.validate import validate
import brute_force

MAIN = os.path.join(ROOT, "main.py")

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print("ok   %s" % name)
    else:
        print("FAIL %s  %s" % (name, detail))
        FAILURES.append(name)


def run_cli(in_text, out_path, workdir):
    in_path = os.path.join(workdir, "in.json")
    with open(in_path, "w", encoding="utf-8") as fh:
        fh.write(in_text)
    return subprocess.run(
        [sys.executable, "-I", MAIN, in_path, out_path],
        capture_output=True, text=True)


def expect_output(name, inp, expected):
    text = json.dumps(inp)
    try:
        got = run_text(text)
        check(name + " [engine]", got == expected,
              "got %s want %s" % (got, expected))
    except Exception as exc:  # noqa: BLE001 - report any engine crash
        check(name + " [engine]", False, "raised %r" % (exc,))
    with tempfile.TemporaryDirectory() as d:
        out_path = os.path.join(d, "out.json")
        proc = run_cli(text, out_path, d)
        if proc.returncode != 0:
            check(name + " [cli]", False,
                  "exit %d stderr %s" % (proc.returncode, proc.stderr))
            return
        with open(out_path, encoding="utf-8") as fh:
            got2 = json.load(fh)
        check(name + " [cli]", got2 == expected,
              "got %s want %s" % (got2, expected))


def expect_error(name, text_or_obj, path):
    text = text_or_obj if isinstance(text_or_obj, str) else json.dumps(text_or_obj)
    try:
        run_text(text)
        check(name + " [engine]", False, "no InputError raised")
    except InputError as exc:
        check(name + " [engine]", exc.path == path,
              "path %s want %s" % (exc.path, path))
    with tempfile.TemporaryDirectory() as d:
        out_path = os.path.join(d, "out.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("OLD")
        proc = run_cli(text, out_path, d)
        with open(out_path, encoding="utf-8") as fh:
            preserved = fh.read() == "OLD"
        check(name + " [cli]",
              proc.returncode == 1 and proc.stderr.strip() == path and preserved,
              "exit %d stderr %r preserved %s"
              % (proc.returncode, proc.stderr, preserved))


# ---------------------------------------------------------------- directed

def item(key, ids, start, end):
    return {"key": key, "ids": ids, "start": start, "end": end}


def directed_valid():
    cases = []
    # the example from the spec: R@2 inside (0,4) negates the segment
    cases.append(("spec-example",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], ["R"]],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 4],
                           ["r", "k", "R", 2], 5]},
                  [[]]))
    # blocker exactly at the right edge: open interval -> kept
    cases.append(("blocker-at-right-edge",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], ["R"]],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 4],
                           ["r", "k", "R", 4], 5]},
                  [[item("k", ["a", "b"], 0, 4)]]))
    # blocker before the window -> kept
    cases.append(("blocker-before-window",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], ["R"]],
                   "ops": [["a", "k", "A", 0], ["r", "k", "R", 0],
                           ["b", "k", "B", 4], 5]},
                  [[item("k", ["a", "b"], 0, 4)]]))
    # blocker after the window -> kept
    cases.append(("blocker-after-window",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], ["R"]],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 4],
                           ["r", "k", "R", 5], 5]},
                  [[item("k", ["a", "b"], 0, 4)]]))
    # blocker of another key does not negate
    cases.append(("blocker-other-key",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], ["R"]],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 4],
                           ["r", "other", "R", 2], 5]},
                  [[item("k", ["a", "b"], 0, 4)]]))
    # blocker type not listed in b does not negate
    cases.append(("blocker-type-unlisted",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], ["X"]],
                   "ops": [["a", "k", "A", 0], ["r", "k", "R", 2],
                           ["b", "k", "B", 4], 5]},
                  [[item("k", ["a", "b"], 0, 4)]]))
    # g bounds
    for tag, t_b, expect in (("gap-below", 1, [[]]),
                             ("gap-at-lo", 2, [[item("k", ["a", "b"], 0, 2)]]),
                             ("gap-at-hi", 3, [[item("k", ["a", "b"], 0, 3)]]),
                             ("gap-above", 4, [[]])):
        cases.append((tag,
                      {"span": 9, "pattern": ["seq", "A", "B", [2, 3], []],
                       "ops": [["a", "k", "A", 0], ["b", "k", "B", t_b], 20]},
                      expect))
    # span filter: duration 6 > 5 dropped, duration 5 kept
    cases.append(("span-drops",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 9], []],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 6], 20]},
                  [[]]))
    cases.append(("span-keeps-edge",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 9], []],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 5], 20]},
                  [[item("k", ["a", "b"], 0, 5)]]))
    # or: union and dedup of identical branches
    cases.append(("or-dedup",
                  {"span": 5, "pattern": ["or", "A", "A"],
                   "ops": [["a", "k", "A", 3], 8]},
                  [[item("k", ["a"], 3, 3)]]))
    cases.append(("or-union",
                  {"span": 5, "pattern": ["or", "A", "B"],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 1], 6]},
                  [[item("k", ["a"], 0, 0), item("k", ["b"], 1, 1)]]))
    cases.append(("or-identical-seqs",
                  {"span": 5,
                   "pattern": ["or", ["seq", "A", "B", [0, 5], []],
                               ["seq", "A", "B", [0, 5], []]],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 1], 5]},
                  [[item("k", ["a", "b"], 0, 1)]]))
    # rep: all of 2..3 repetitions
    cases.append(("rep-basic",
                  {"span": 10, "pattern": ["rep", "A", 2, 3, [0, 2], []],
                   "ops": [["a1", "k", "A", 0], ["a2", "k", "A", 1],
                           ["a3", "k", "A", 2], 12]},
                  [[item("k", ["a1", "a2"], 0, 1),
                    item("k", ["a1", "a2", "a3"], 0, 2),
                    item("k", ["a1", "a3"], 0, 2),
                    item("k", ["a2", "a3"], 1, 2)]]))
    # rep: per-match publish timing inside one pattern
    cases.append(("rep-publish-timing",
                  {"span": 5, "pattern": ["rep", "A", 1, 2, [0, 1], []],
                   "ops": [["a1", "k", "A", 0], ["a2", "k", "A", 1], 5, 6]},
                  [[item("k", ["a1"], 0, 0), item("k", ["a1", "a2"], 0, 1)],
                   [item("k", ["a2"], 1, 1)]]))
    # rep negated by a recovery event at a repetition boundary
    cases.append(("rep-blocked",
                  {"span": 9, "pattern": ["rep", "A", 2, 2, [0, 3], ["R"]],
                   "ops": [["a1", "k", "A", 0], ["a2", "k", "A", 2],
                           ["r", "k", "R", 1], 9]},
                  [[]]))
    cases.append(("rep-unblocked",
                  {"span": 9, "pattern": ["rep", "A", 2, 2, [0, 3], ["R"]],
                   "ops": [["a1", "k", "A", 0], ["a2", "k", "A", 2], 9]},
                  [[item("k", ["a1", "a2"], 0, 2)]]))
    # watermark timing: exact boundary, empty batches, no republish
    cases.append(("wm-timing",
                  {"span": 5, "pattern": "A",
                   "ops": [["a", "k", "A", 0], 4, ["b", "k", "A", 5], 5, 10]},
                  [[], [item("k", ["a"], 0, 0)], [item("k", ["b"], 5, 5)]]))
    cases.append(("wm-noop",
                  {"span": 5, "pattern": "A",
                   "ops": [["a", "k", "A", 0], 5, 5, 6]},
                  [[item("k", ["a"], 0, 0)], [], []]))
    cases.append(("wm-minus-one-noop",
                  {"span": 5, "pattern": "A",
                   "ops": [["a", "k", "A", 0], -1, 5]},
                  [[], [item("k", ["a"], 0, 0)]]))
    cases.append(("wm-crosses-later",
                  {"span": 5, "pattern": "A",
                   "ops": [["a", "k", "A", 2], 6, 7]},
                  [[], [item("k", ["a"], 2, 2)]]))
    # EOF does not advance the watermark
    cases.append(("eof-no-publish",
                  {"span": 5, "pattern": "A", "ops": [["a", "k", "A", 0]]},
                  []))
    cases.append(("eof-no-publish-2",
                  {"span": 5, "pattern": "A", "ops": [["a", "k", "A", 0], 4]},
                  [[]]))
    cases.append(("empty-ops", {"span": 1, "pattern": "A", "ops": []}, []))
    cases.append(("wm-only", {"span": 1, "pattern": "A", "ops": [3]}, [[]]))
    # same timestamp: ordered by id
    cases.append(("same-t-id-order",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 0], []],
                   "ops": [["a1", "k", "A", 2], ["b1", "k", "B", 2], 7]},
                  [[item("k", ["a1", "b1"], 2, 2)]]))
    cases.append(("same-t-id-order-bad",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 0], []],
                   "ops": [["a0", "k", "B", 2], ["z9", "k", "A", 2], 7]},
                  [[]]))
    # sorting: by key, then ids (ASCII)
    cases.append(("sorting",
                  {"span": 3, "pattern": "A",
                   "ops": [["e1", "k2", "A", 0], ["e2", "k1", "A", 0],
                           ["e3", "k1", "A", 1], 4]},
                  [[item("k1", ["e2"], 0, 0), item("k1", ["e3"], 1, 1),
                    item("k2", ["e1"], 0, 0)]]))
    # overlapping results are all kept
    cases.append(("overlap-kept",
                  {"span": 5, "pattern": ["seq", "A", "B", [0, 5], []],
                   "ops": [["a", "k", "A", 0], ["b1", "k", "B", 1],
                           ["b2", "k", "B", 2], 5]},
                  [[item("k", ["a", "b1"], 0, 1),
                    item("k", ["a", "b2"], 0, 2)]]))
    # no event reuse
    cases.append(("no-reuse",
                  {"span": 5, "pattern": ["seq", "A", "A", [0, 5], []],
                   "ops": [["a", "k", "A", 1], 10]},
                  [[]]))
    # nested patterns
    cases.append(("nested-or",
                  {"span": 6,
                   "pattern": ["seq", ["or", "A", "B"], "C", [0, 3], ["R"]],
                   "ops": [["a", "k", "A", 0], ["x", "k", "B", 1],
                           ["c", "k", "C", 3], 7]},
                  [[item("k", ["a", "c"], 0, 3),
                    item("k", ["x", "c"], 1, 3)]]))
    cases.append(("nested-seq",
                  {"span": 9,
                   "pattern": ["seq", ["seq", "A", "B", [0, 2], []], "C",
                               [0, 2], []],
                   "ops": [["a", "k", "A", 0], ["b", "k", "B", 1],
                           ["c", "k", "C", 2], 11]},
                  [[item("k", ["a", "b", "c"], 0, 2)]]))
    # a leaf type may be named like an operator
    cases.append(("leaf-named-or",
                  {"span": 2, "pattern": "or",
                   "ops": [["a", "k", "or", 0], 2]},
                  [[item("k", ["a"], 0, 0)]]))
    # out-of-order arrival
    cases.append(("out-of-order",
                  {"span": 5, "pattern": "A",
                   "ops": [["b", "k", "A", 5], ["a", "k", "A", 0], 5]},
                  [[item("k", ["a"], 0, 0)]]))
    # several keys matched independently; cross-key never matches
    cases.append(("multi-key",
                  {"span": 4, "pattern": ["seq", "A", "B", [0, 2], []],
                   "ops": [["a1", "k1", "A", 0], ["b1", "k1", "B", 1],
                           ["a2", "k2", "A", 0], ["b2", "k2", "B", 2], 4]},
                  [[item("k1", ["a1", "b1"], 0, 1),
                    item("k2", ["a2", "b2"], 0, 2)]]))
    cases.append(("cross-key-none",
                  {"span": 4, "pattern": ["seq", "A", "B", [0, 2], []],
                   "ops": [["a", "k1", "A", 0], ["b", "k2", "B", 1], 4]},
                  [[]]))
    for name, inp, expected in cases:
        expect_output(name, inp, expected)


def directed_invalid():
    cases = [
        # syntax errors -> $
        ("syntax-truncated", "{", "$"),
        ("syntax-trailing-comma",
         '{"span":1,"pattern":"A","ops":[],}', "$"),
        ("syntax-garbage", "not json", "$"),
        ("syntax-deep-nesting", "[" * 5000 + "]" * 5000, "$"),
        ("syntax-nan", '{"span":NaN,"pattern":"A","ops":[]}', "$"),
        ("dup-member", '{"span":1,"span":1,"pattern":"A","ops":[]}', "$"),
        # root shape
        ("root-array", [1, 2, 3], "$"),
        ("root-null", None, "$"),
        ("root-string", '"hello"', "$"),
        ("missing-ops", {"span": 1, "pattern": "A"}, "$"),
        ("missing-span", {"pattern": "A", "ops": []}, "$"),
        ("missing-pattern", {"span": 1, "ops": []}, "$"),
        ("unknown-member",
         {"span": 1, "pattern": "A", "ops": [], "x": 0}, "$.x"),
        # span
        ("span-bool", {"span": True, "pattern": "A", "ops": []}, "$.span"),
        ("span-zero", {"span": 0, "pattern": "A", "ops": []}, "$.span"),
        ("span-negative", {"span": -3, "pattern": "A", "ops": []}, "$.span"),
        ("span-float", {"span": 2.5, "pattern": "A", "ops": []}, "$.span"),
        ("span-string", {"span": "5", "pattern": "A", "ops": []}, "$.span"),
        ("span-null", {"span": None, "pattern": "A", "ops": []}, "$.span"),
        # pattern
        ("pattern-number", {"span": 1, "pattern": 42, "ops": []}, "$.pattern"),
        ("pattern-bool", {"span": 1, "pattern": True, "ops": []}, "$.pattern"),
        ("pattern-null", {"span": 1, "pattern": None, "ops": []}, "$.pattern"),
        ("pattern-empty-str", {"span": 1, "pattern": "", "ops": []}, "$.pattern"),
        ("pattern-bad-ident",
         {"span": 1, "pattern": "A B", "ops": []}, "$.pattern"),
        ("pattern-non-ascii",
         {"span": 1, "pattern": "á", "ops": []}, "$.pattern"),
        ("pattern-empty-array", {"span": 1, "pattern": [], "ops": []}, "$.pattern"),
        ("pattern-bad-op",
         {"span": 1, "pattern": ["xor", "A", "B"], "ops": []}, "$.pattern[0]"),
        ("pattern-op-not-string",
         {"span": 1, "pattern": [1, "A", "B"], "ops": []}, "$.pattern[0]"),
        ("or-arity-low",
         {"span": 1, "pattern": ["or", "A"], "ops": []}, "$.pattern"),
        ("or-arity-high",
         {"span": 1, "pattern": ["or", "A", "B", "C"], "ops": []}, "$.pattern"),
        ("or-bad-child",
         {"span": 1, "pattern": ["or", "A", 7], "ops": []}, "$.pattern[2]"),
        ("seq-arity",
         {"span": 1, "pattern": ["seq", "A", "B"], "ops": []}, "$.pattern"),
        ("seq-g-not-array",
         {"span": 1, "pattern": ["seq", "A", "B", "g", []], "ops": []},
         "$.pattern[3]"),
        ("seq-g-arity",
         {"span": 1, "pattern": ["seq", "A", "B", [0], []], "ops": []},
         "$.pattern[3]"),
        ("seq-g-inverted",
         {"span": 1, "pattern": ["seq", "A", "B", [3, 1], []], "ops": []},
         "$.pattern[3]"),
        ("seq-g-negative",
         {"span": 1, "pattern": ["seq", "A", "B", [-1, 1], []], "ops": []},
         "$.pattern[3][0]"),
        ("seq-g-bool",
         {"span": 1, "pattern": ["seq", "A", "B", [0, True], []], "ops": []},
         "$.pattern[3][1]"),
        ("seq-b-not-array",
         {"span": 1, "pattern": ["seq", "A", "B", [0, 1], "R"], "ops": []},
         "$.pattern[4]"),
        ("seq-b-dup",
         {"span": 1, "pattern": ["seq", "A", "B", [0, 1], ["R", "R"]],
          "ops": []}, "$.pattern[4][1]"),
        ("seq-b-dup-late",
         {"span": 1, "pattern": ["seq", "A", "B", [0, 1], ["R", "X", "R"]],
          "ops": []}, "$.pattern[4][2]"),
        ("seq-b-bad-type",
         {"span": 1, "pattern": ["seq", "A", "B", [0, 1], ["R", 1]],
          "ops": []}, "$.pattern[4][1]"),
        ("seq-b-empty-type",
         {"span": 1, "pattern": ["seq", "A", "B", [0, 1], [""]],
          "ops": []}, "$.pattern[4][0]"),
        ("rep-arity",
         {"span": 1, "pattern": ["rep", "A", 1, 2, [0, 1]], "ops": []},
         "$.pattern"),
        ("rep-m-zero",
         {"span": 1, "pattern": ["rep", "A", 0, 2, [0, 1], []], "ops": []},
         "$.pattern[2]"),
        ("rep-m-float",
         {"span": 1, "pattern": ["rep", "A", 1.5, 2, [0, 1], []], "ops": []},
         "$.pattern[2]"),
        ("rep-n-bool",
         {"span": 1, "pattern": ["rep", "A", 1, True, [0, 1], []], "ops": []},
         "$.pattern[3]"),
        ("rep-m-gt-n",
         {"span": 1, "pattern": ["rep", "A", 3, 2, [0, 1], []], "ops": []},
         "$.pattern[3]"),
        ("rep-b-not-array",
         {"span": 1, "pattern": ["rep", "A", 1, 2, [0, 1], "b"], "ops": []},
         "$.pattern[5]"),
        ("rep-bad-child",
         {"span": 1, "pattern": ["rep", 1, 1, 2, [0, 1], []], "ops": []},
         "$.pattern[1]"),
        ("nested-error-path",
         {"span": 1, "pattern": ["seq", ["or", "A", 5], "B", [0, 1], []],
          "ops": []}, "$.pattern[1][2]"),
        ("deep-error-path",
         {"span": 1, "pattern": ["rep", "A", 1, 2, [0, 1], ["R", "R"]],
          "ops": []}, "$.pattern[5][1]"),
        # ops
        ("ops-not-array", {"span": 1, "pattern": "A", "ops": {}}, "$.ops"),
        ("ops-string", {"span": 1, "pattern": "A", "ops": "x"}, "$.ops"),
        ("op-string", {"span": 1, "pattern": "A", "ops": ["x"]}, "$.ops[0]"),
        ("op-bool", {"span": 1, "pattern": "A", "ops": [True]}, "$.ops[0]"),
        ("op-float", {"span": 1, "pattern": "A", "ops": [1.5]}, "$.ops[0]"),
        ("op-null", {"span": 1, "pattern": "A", "ops": [None]}, "$.ops[0]"),
        ("event-arity-low",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "A"]]}, "$.ops[0]"),
        ("event-arity-high",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "A", 0, "x"]]},
         "$.ops[0]"),
        ("event-id-empty",
         {"span": 1, "pattern": "A", "ops": [["", "k", "A", 0]]},
         "$.ops[0][0]"),
        ("event-id-not-string",
         {"span": 1, "pattern": "A", "ops": [[7, "k", "A", 0]]},
         "$.ops[0][0]"),
        ("event-id-bad-chars",
         {"span": 1, "pattern": "A", "ops": [["a b", "k", "A", 0]]},
         "$.ops[0][0]"),
        ("event-key-bad",
         {"span": 1, "pattern": "A", "ops": [["a", "k!", "A", 0]]},
         "$.ops[0][1]"),
        ("event-type-empty",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "", 0]]},
         "$.ops[0][2]"),
        ("event-type-null",
         {"span": 1, "pattern": "A", "ops": [["a", "k", None, 0]]},
         "$.ops[0][2]"),
        ("event-t-negative",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "A", -1]]},
         "$.ops[0][3]"),
        ("event-t-bool",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "A", False]]},
         "$.ops[0][3]"),
        ("event-t-float",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "A", 0.5]]},
         "$.ops[0][3]"),
        ("event-t-string",
         {"span": 1, "pattern": "A", "ops": [["a", "k", "A", "0"]]},
         "$.ops[0][3]"),
        ("event-dup-id",
         {"span": 1, "pattern": "A",
          "ops": [["a", "k", "A", 0], ["a", "k", "B", 1]]}, "$.ops[1][0]"),
        ("wm-decreasing",
         {"span": 1, "pattern": "A", "ops": [3, 2]}, "$.ops[1]"),
        ("wm-below-minus-one",
         {"span": 1, "pattern": "A", "ops": [-2]}, "$.ops[0]"),
        ("event-t-eq-wm",
         {"span": 1, "pattern": "A", "ops": [3, ["a", "k", "A", 3]]},
         "$.ops[1][3]"),
        ("event-t-lt-wm",
         {"span": 1, "pattern": "A", "ops": [3, ["a", "k", "A", 2]]},
         "$.ops[1][3]"),
    ]
    for name, text_or_obj, path in cases:
        expect_error(name, text_or_obj, path)


# ---------------------------------------------------------------- random

def random_pattern(rng, types, depth):
    if depth <= 0 or rng.random() < 0.45:
        return rng.choice(types)
    op = rng.choice(("or", "seq", "rep"))
    if op == "or":
        return ["or", random_pattern(rng, types, depth - 1),
                random_pattern(rng, types, depth - 1)]
    lo = rng.randint(0, 3)
    hi = lo + rng.randint(0, 3)
    blockers = rng.sample(types, rng.randint(0, 2))
    if op == "seq":
        return ["seq", random_pattern(rng, types, depth - 1),
                random_pattern(rng, types, depth - 1), [lo, hi], blockers]
    m = rng.randint(1, 2)
    n = m + rng.randint(0, 2)
    return ["rep", random_pattern(rng, types, depth - 1), m, n,
            [lo, hi], blockers]


def random_input(rng):
    types = ["A", "B", "C", "R"]
    keys = ["k1", "k2"]
    span = rng.randint(1, 8)
    pattern = random_pattern(rng, types, rng.randint(1, 3))
    ops = []
    watermark = -1
    eid = 0
    for _ in range(rng.randint(1, 12)):
        if rng.random() < 0.30:
            watermark += rng.randint(0, 4)
            ops.append(watermark)
        else:
            t = watermark + 1 + rng.randint(0, 5)
            ops.append(["e%d" % eid, rng.choice(keys), rng.choice(types), t])
            eid += 1
    return {"span": span, "pattern": pattern, "ops": ops}


def check_invariants(name, inp, result):
    problems = []
    wm_ops = [o for o in inp["ops"] if isinstance(o, int)]
    if len(result) != len(wm_ops):
        problems.append("batch count %d != watermark ops %d"
                        % (len(result), len(wm_ops)))
        return problems
    events = {o[0]: o for o in inp["ops"] if isinstance(o, list)}
    seen = set()
    watermark = -1
    wi = 0
    for o in inp["ops"]:
        if not isinstance(o, int):
            continue
        batch = result[wi]
        wi += 1
        keys = [(it["key"], it["ids"]) for it in batch]
        if keys != sorted(keys):
            problems.append("batch %d not sorted" % wi)
        for it in batch:
            idt = tuple(it["ids"])
            if idt in seen:
                problems.append("id sequence %s published twice" % (idt,))
            seen.add(idt)
            evs = [events[i] for i in it["ids"]]
            order = [(e[3], e[0]) for e in evs]
            if order != sorted(order) or len(set(order)) != len(order):
                problems.append("ids %s not strictly increasing" % (idt,))
            if any(e[1] != it["key"] for e in evs):
                problems.append("ids %s: mixed keys" % (idt,))
            if it["start"] != evs[0][3] or it["end"] != evs[-1][3]:
                problems.append("ids %s: bad start/end" % (idt,))
            if not 0 <= it["end"] - it["start"] <= inp["span"]:
                problems.append("ids %s: span violated" % (idt,))
            if not watermark < it["start"] + inp["span"] <= o:
                problems.append("ids %s: published at wrong watermark" % (idt,))
        watermark = o
    return problems


def randomized(count, seed):
    rng = random.Random(seed)
    bad = 0
    for i in range(count):
        inp = random_input(rng)
        text = json.dumps(inp)
        name = "random-%d" % i
        try:
            got = run_text(text)
        except Exception as exc:  # noqa: BLE001
            check(name, False, "engine raised %r on %s" % (exc, text))
            bad += 1
            continue
        span, pattern, ops = validate(json.loads(text))
        want = brute_force.expected_output(span, pattern, ops)
        problems = check_invariants(name, inp, got)
        if got != want:
            problems.append("mismatch:\n  input %s\n  got  %s\n  want %s"
                            % (text, got, want))
        if problems:
            bad += 1
            check(name, False, "; ".join(problems)[:2000])
        if bad >= 5:
            break
    check("randomized-%d-cases" % count, bad == 0, "%d failing cases" % bad)


def end_to_end_random(count, seed):
    rng = random.Random(seed)
    bad = 0
    for i in range(count):
        inp = random_input(rng)
        text = json.dumps(inp)
        span, pattern, ops = validate(json.loads(text))
        want = brute_force.expected_output(span, pattern, ops)
        with tempfile.TemporaryDirectory() as d:
            out_path = os.path.join(d, "out.json")
            proc = run_cli(text, out_path, d)
            if proc.returncode != 0:
                check("e2e-%d" % i, False,
                      "exit %d stderr %s input %s"
                      % (proc.returncode, proc.stderr, text))
                bad += 1
                continue
            with open(out_path, encoding="utf-8") as fh:
                got = json.load(fh)
            if got != want:
                check("e2e-%d" % i, False,
                      "input %s\n got %s\n want %s" % (text, got, want))
                bad += 1
        if bad >= 5:
            break
    check("end-to-end-%d-cases" % count, bad == 0, "%d failing cases" % bad)


# ---------------------------------------------------------------- fuzz

def random_json_value(rng, depth):
    if depth <= 0:
        return rng.choice([0, 1, -1, True, False, None, "A", "", 1.5, "x"])
    choice = rng.randint(0, 6)
    if choice == 0:
        return rng.randint(-5, 20)
    if choice == 1:
        return rng.choice([True, False, None])
    if choice == 2:
        return "".join(rng.choice("abAB12 !") for _ in range(rng.randint(0, 4)))
    if choice == 3:
        return rng.choice([0.5, -1.25, 1e3])
    if choice == 4:
        return [random_json_value(rng, depth - 1)
                for _ in range(rng.randint(0, 5))]
    if choice == 5:
        return {rng.choice(["span", "pattern", "ops", "x", "A"]):
                random_json_value(rng, depth - 1)
                for _ in range(rng.randint(0, 4))}
    return rng.choice(["or", "seq", "rep", "A", "B"])


def mutate(rng, inp):
    obj = copy.deepcopy(inp)
    kind = rng.randint(0, 7)
    if kind == 0:
        obj["span"] = rng.choice([0, -1, 1.5, "x", True, None])
    elif kind == 1:
        obj["pattern"] = rng.choice(
            [0, None, "", ["or"], ["seq", "A", "B"],
             ["rep", "A", 0, 1, [0, 1], []], ["xor", "A", "B"]])
    elif kind == 2:
        obj["unknown"] = 1
    elif kind == 3:
        evs = [o for o in obj["ops"] if isinstance(o, list)]
        if len(evs) >= 2:
            evs[1][0] = evs[0][0]
        else:
            obj["ops"] = [["a", "k", "A", 0], ["a", "k", "B", 1]]
    elif kind == 4:
        obj["ops"] = [3, 1]
    elif kind == 5:
        obj["ops"] = [5, ["a", "k", "A", 5]]
    elif kind == 6:
        obj["ops"] = [["a", "k", "A", rng.choice([-1, True, 0.5, "0"])]]
    else:
        obj.pop(rng.choice(["span", "pattern", "ops"]), None)
    return obj


def fuzz(count, seed):
    rng = random.Random(seed)
    bad = 0
    for i in range(count):
        style = rng.random()
        if style < 0.45:
            text = json.dumps(mutate(rng, random_input(rng)))
        elif style < 0.9:
            text = json.dumps(random_json_value(rng, 3))
        else:
            text = json.dumps(random_input(rng))[:rng.randint(1, 40)]
        with tempfile.TemporaryDirectory() as d:
            out_path = os.path.join(d, "out.json")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write("OLD")
            proc = run_cli(text, out_path, d)
            with open(out_path, encoding="utf-8") as fh:
                preserved = fh.read() == "OLD"
            if proc.returncode == 0:
                try:
                    span, pattern, ops = validate(json.loads(text))
                    want = brute_force.expected_output(span, pattern, ops)
                    with open(out_path, encoding="utf-8") as fh:
                        got = json.load(fh)
                    ok = got == want
                except InputError:
                    ok = False
                if not ok:
                    bad += 1
                    check("fuzz-%d" % i, False,
                          "valid input disagrees with brute force: %s" % text)
            elif proc.returncode == 1:
                if not (proc.stderr.strip().startswith("$") and preserved):
                    bad += 1
                    check("fuzz-%d" % i, False,
                          "bad rejection: stderr %r preserved %s"
                          % (proc.stderr, preserved))
            else:
                bad += 1
                check("fuzz-%d" % i, False,
                      "unexpected exit %d stderr %s"
                      % (proc.returncode, proc.stderr))
        if bad >= 5:
            break
    check("fuzz-%d-cases" % count, bad == 0, "%d failing cases" % bad)


# ------------------------------------------------------- files & smoke

def file_behaviour():
    with tempfile.TemporaryDirectory() as d:
        out_path = os.path.join(d, "out.json")
        good = json.dumps({"span": 5, "pattern": "A",
                           "ops": [["a", "k", "A", 0], 5]})
        bad = json.dumps({"span": 5, "pattern": "A", "ops": [3, 1]})

        # success creates the output
        proc = run_cli(good, out_path, d)
        ok = proc.returncode == 0 and os.path.exists(out_path)
        if ok:
            with open(out_path, encoding="utf-8") as fh:
                ok = json.load(fh) == [[item("k", ["a"], 0, 0)]]
        check("file-created-on-success", ok,
              "exit %d stderr %s" % (proc.returncode, proc.stderr))

        # success replaces an old output
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("OLD")
        proc = run_cli(good, out_path, d)
        with open(out_path, encoding="utf-8") as fh:
            replaced = json.load(fh) == [[item("k", ["a"], 0, 0)]]
        check("file-replaced-on-success",
              proc.returncode == 0 and replaced, "stderr %s" % proc.stderr)

        # failure keeps the old output
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("OLD")
        proc = run_cli(bad, out_path, d)
        with open(out_path, encoding="utf-8") as fh:
            kept = fh.read() == "OLD"
        check("file-kept-on-failure",
              proc.returncode == 1 and proc.stderr.strip() == "$.ops[1]"
              and kept, "exit %d stderr %s" % (proc.returncode, proc.stderr))

        # failure does not create a missing output
        os.unlink(out_path)
        proc = run_cli(bad, out_path, d)
        check("file-not-created-on-failure",
              proc.returncode == 1 and not os.path.exists(out_path),
              "exit %d" % proc.returncode)

        # missing input file -> exit 2
        proc = subprocess.run(
            [sys.executable, "-I", MAIN,
             os.path.join(d, "nope.json"), out_path],
            capture_output=True, text=True)
        check("missing-input-exit-2", proc.returncode == 2,
              "exit %d" % proc.returncode)


def perf_smoke():
    # 3000 leaf matches
    ops = [["e%d" % i, "k", "A", i] for i in range(3000)] + [4000]
    got = run_text(json.dumps({"span": 5, "pattern": "A", "ops": ops}))
    check("smoke-leaf-3000",
          len(got) == 1 and len(got[0]) == 3000
          and got[0][0] == item("k", ["e0"], 0, 0),
          "batches %s" % ([len(b) for b in got],))

    # 100 x 100 seq matches on one key
    ops = [["a%d" % i, "k", "A", i] for i in range(100)]
    ops += [["b%d" % i, "k", "B", 100 + i] for i in range(100)]
    ops.append(1000)
    got = run_text(json.dumps(
        {"span": 400, "pattern": ["seq", "A", "B", [0, 200], []],
         "ops": ops}))
    batch = got[0] if got else []
    keys = [(it["key"], it["ids"]) for it in batch]
    check("smoke-seq-10000",
          len(batch) == 10000 and keys == sorted(keys)
          and item("k", ["a0", "b0"], 0, 100) in batch
          and item("k", ["a99", "b99"], 99, 199) in batch,
          "batch size %d" % len(batch))


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20261114
    directed_valid()
    directed_invalid()
    randomized(count, seed)
    end_to_end_random(max(10, count // 30), seed + 1)
    fuzz(max(20, count // 8), seed + 2)
    file_behaviour()
    perf_smoke()
    if FAILURES:
        print("\n%d FAILURE(S)" % len(FAILURES))
        return 1
    print("\nall acceptance tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
