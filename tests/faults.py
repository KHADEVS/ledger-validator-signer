"""Breaks the app on purpose, one fault at a time. Every fault must make the test suite fail.

Environment: BUILD (default "make TEST_BUILD=1"), run from the root of the repository.
"""
import os
import subprocess
import sys

SOURCE = "src/handler/validator.c"
BUILD = os.environ.get("BUILD", "make TEST_BUILD=1")

FAULTS = [
    ("surround vote allowed", "source < m.source || target <= m.target", "target <= m.target"),
    ("double vote allowed", "source < m.source || target <= m.target", "source < m.source || target < m.target"),
    ("double block allowed", "slot <= m.block_slot", "slot < m.block_slot"),
    ("record never written", "    nvm_write((void *) &N_nv.marks[key][m->seq % 2], m, sizeof(*m));\n", ""),
    ("network not checked", "memcmp((const void *) N_nv.genesis_root, d + 8, 32) != 0", "0"),
    ("wrong attestation domain", "signing_root(object, 0x01", "signing_root(object, 0x02"),
    ("block fields swapped", "leaf_u64(leaf[1], h + 8);", "leaf_u64(leaf[1], h);"),
    ("wrong network name", '{"Hoodi",', '{"Mainnet",'),
    ("another network stored than the one shown", "nvm_write((void *) N_nv.genesis_root, g_pending_root, 32);",
     "g_pending_root[31] ^= 1; nvm_write((void *) N_nv.genesis_root, g_pending_root, 32);"),
]


def run():
    subprocess.run(BUILD, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = subprocess.run([sys.executable, "tests/run.py"], capture_output=True, text=True).stdout
    return out.count("\nFAIL") + out.startswith("FAIL"), "ALL PASSED" in out


original = open(SOURCE).read()
missed = []
try:
    for name, old, new in FAULTS:
        assert original.count(old) == 1, f"{name}: not applied"
        open(SOURCE, "w").write(original.replace(old, new))
        fails, passed = run()
        print(f"{name}: {'MISSED' if passed or not fails else f'caught, {fails} tests fail'}", flush=True)
        if passed or not fails:
            missed.append(name)
finally:
    open(SOURCE, "w").write(original)
fails, passed = run()
print(f"without any fault: {'ALL PASSED' if passed else 'FAILED'}")
sys.exit(bool(missed) or not passed)
