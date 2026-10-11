#!/usr/bin/env python3
"""Mutation check for tests/toolchain_pin_test.sh's --self-test legs.

A leg written alongside a fix asserts on output the fix already produces. That
proves the fix works; it does NOT prove the leg would notice if the fix were
removed, and noticing is the only reason the leg exists. The two look identical
from a green run -- which is the same subset-reads-as-coverage shape the guard
itself is about, one level up.

So: revert each arm ALONE, confirm --self-test goes red. One mutation per run,
restored in between -- reverting two together lets one mask the other.

Run this by hand after editing the guard. It is deliberately not in CI: it
rewrites the file under test, and its value is at edit time, not per-push.

Exact string replacement, not sed: the metacharacter-dense patterns below
(`[[:space:];&|(]`, `\\+[^[:space:]]+`) are the reason -- the first attempt at
this measurement used sed, three mutations silently matched nothing, and four
live findings scored as clean. Hence the anchor-count assertion: a mutation
that does not land must be loud, never a PASS.
"""
import pathlib
import subprocess
import sys

SCRIPT = pathlib.Path(__file__).with_name("toolchain_pin_test.sh")
ORIGINAL = SCRIPT.read_text()

# (what is being reverted, exact text in the script, what it becomes)
MUTATIONS = [
    ("sep class: drop &",       "[[:space:];&|(]",    "[[:space:];|(]"),
    ("sep class: drop (",       "[[:space:];&|(]",    "[[:space:];&|]"),
    ("sep class: drop ;",       "[[:space:];&|(]",    "[[:space:]&|(]"),
    ("sep class: drop |",       "[[:space:];&|(]",    "[[:space:];&(]"),
    ("sep class: space only",   "[[:space:];&|(]",    "[[:space:]]"),
    ("verb tail: space or EOL", "([^[:alnum:]_-]|$)", "([[:space:]]|$)"),
    ("verb: no +toolchain",     "(\\+[^[:space:]]+[[:space:]]+)?", ""),
    ("awk: blank from any #",   'sub(/(^|[[:space:]])#.*/, "", l)', 'sub(/#.*/, "", l)'),
    ("per-file guard: no [a-z]", "'[[:space:]]cargo[[:space:]][a-z]'",
                                 "'[[:space:]]cargo[[:space:]]'"),
    ("per-file guard: off",     'if [ "$found" -eq 0 ] && printf',
                                'if [ "$found" -eq 99 ] && printf'),
    ("pin glob: *.yml",         "dtolnay/rust-toolchain@' .github/workflows/*.y*ml",
                                "dtolnay/rust-toolchain@' .github/workflows/*.yml"),
    ("cargo glob: *.yml",       "for wf in .github/workflows/*.y*ml; do",
                                "for wf in .github/workflows/*.yml; do"),
    ("global calls>0: off",     '[ "$calls" -gt 0 ] ||', '[ "$calls" -gt -1 ] ||'),
]


def self_test() -> str:
    run = subprocess.run(["bash", str(SCRIPT), "--self-test"],
                         capture_output=True, text=True, cwd=SCRIPT.parent.parent)
    return (run.stdout + run.stderr).strip().splitlines()[-1]


def main() -> int:
    baseline = self_test()
    if not baseline.startswith("PASS"):
        print(f"unmutated --self-test is not green, nothing below means anything: {baseline}")
        return 2

    survivors = []
    try:
        for label, old, new in MUTATIONS:
            hits = ORIGINAL.count(old)
            if hits != 1:
                print(f"  ????  {label:<27} anchor matched {hits}x -- NOT A MEASUREMENT")
                survivors.append(label)
                continue
            SCRIPT.write_text(ORIGINAL.replace(old, new))
            assert SCRIPT.read_text() != ORIGINAL, f"{label}: mutation did not land"
            line = self_test()
            SCRIPT.write_text(ORIGINAL)
            caught = line.startswith("FAIL")
            print(f"  {'red ' if caught else 'GREEN'}  {label:<27} {line}")
            if not caught:
                survivors.append(label)
    finally:
        SCRIPT.write_text(ORIGINAL)

    print(f"\n{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} arms have a failing mutation")
    if survivors:
        print("NO FAILING MUTATION -- these arms are comments, not guards:")
        for s in survivors:
            print(f"  - {s}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
