"""Breaks the app on purpose, one fault at a time. Every fault must make the test suite fail.

Environment: BUILD (default "make TEST_BUILD=1"), AFTER (a command run after each suite, for
example to stop an emulator left behind). Run from the root of the repository.
"""
import os
import subprocess
import sys

SOURCE = "src/handler/validator.c"
BUILD = os.environ.get("BUILD", "make TEST_BUILD=1")
AFTER = os.environ.get("AFTER")

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
    ("exit signed without a press", "    g_pending = true;\n    ui_confirm(2, exit_choice);",
     "    g_pending = true;\n    exit_choice(true);"),
    ("exit signed as an attestation", "signing_root(object, 0x04", "signing_root(object, 0x01"),
    ("registration for any fee recipient", "N_nv.fee_set != 1 || memcmp((const void *) N_nv.fee, r, 28) != 0", "0"),
    ("length of the bit list left out", "hash2(a, b, g_stream.inner[0]); /* the length is mixed in */",
     "memcpy(g_stream.inner[0], a, 32);"),
    ("end bit kept in the bit list", "            byte &= (uint8_t) ~(1u << top);\n", ""),
    ("aggregate signed without all its bits",
     "        if (g_stream.received != g_stream.bits_len) {\n            return io_send_sw(SW_BAD_DUTY);\n        }\n", ""),
    ("aggregate finished for another network",
     "    int sw = check_duty(g_stream.header, &key);\n    if (sw != 0) {\n        return io_send_sw(sw);\n    }\n"
     "    if (g_stream.kind == STREAM_CONTRIBUTION) {",
     "    int sw = 0;\n    key = U4BE(g_stream.header, 0);\n    (void) sw;\n    if (g_stream.kind == STREAM_CONTRIBUTION) {"),
    ("tree of the bit list one level short", "merkle_finish(g_stream.kind == STREAM_AGGREGATE ? 3 : 9, a);",
     "merkle_finish(g_stream.kind == STREAM_AGGREGATE ? 3 : 8, a);"),
    ("Gloas subtrees chained in the wrong order", "hash2(g_stream.subs[count], a, a);", "hash2(a, g_stream.subs[count], a);"),
]


def run():
    """Builds and runs the suite: (the build worked, failed checks, all passed, exit code)."""
    if subprocess.run(BUILD, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        return False, 0, False, 1
    try:
        done = subprocess.run([sys.executable, "tests/run.py"], capture_output=True, text=True, timeout=1500)
        out, code = done.stdout, done.returncode
    except subprocess.TimeoutExpired as stopped:
        out, code = (stopped.stdout or b"").decode(errors="replace"), -1
    if AFTER:
        subprocess.run(AFTER, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, out.count("\nFAIL") + out.startswith("FAIL"), "ALL PASSED" in out, code


original = open(SOURCE).read()
missed = []
try:
    for name, old, new in FAULTS:
        assert original.count(old) == 1, f"{name}: not applied"
        open(SOURCE, "w").write(original.replace(old, new))
        built, fails, passed, code = run()
        if not built:
            verdict = "DID NOT BUILD"
        elif passed or (not fails and code == 0):
            verdict = "MISSED"
        else:
            verdict = f"caught, {fails} checks fail" if fails else "caught, the suite stopped"
        print(f"{name}: {verdict}", flush=True)
        if not verdict.startswith("caught"):
            missed.append(name)
finally:
    open(SOURCE, "w").write(original)
built, fails, passed, code = run()
print(f"without any fault: {'ALL PASSED' if passed else 'FAILED'}")
sys.exit(bool(missed) or not passed)
