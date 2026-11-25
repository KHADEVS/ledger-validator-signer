"""Breaks the app on purpose, one fault at a time. Every fault must make the test suite fail.

Environment: BUILD (default "make TEST_BUILD=1"), AFTER (a command run after each suite, for
example to stop an emulator left behind), ONLY (a word: only the faults whose name holds it).
Run from the root of the repository.
"""
import os
import subprocess
import sys

SOURCE = "src/handler/validator.c"
KEYS = "src/handler/bls_common.c"
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
    ("keys in memory: only the first one is ever derived", "if ((g_sk_known & (1u << key)) == 0) {",
     "if (g_sk_known == 0) {", KEYS),
    ("import: the tag is not checked", "    explicit_bzero(z, sizeof(z));\n    explicit_bzero(prk, sizeof(prk));",
     "    ret = CX_OK;\n    explicit_bzero(z, sizeof(z));\n    explicit_bzero(prk, sizeof(prk));"),
    ("import: a share of zero or above the order is taken",
     "ret != CX_OK || diff >= 0 || cx_math_is_zero(g_import.secret, 32)", "ret != CX_OK"),
    ("import: the starting point is not stored", "        store_mark(MAX_KEYS + slot, &m);\n", ""),
    ("import: importing again lowers the record",
     "    if (N_nv.shares[d[0]].present == 1 &&\n        memcmp((const void *) N_nv.shares[d[0]].group_pk, d + 2, 48) == 0) {\n        mark_t old;",
     "    if (0) {\n        mark_t old;"),
    ("import: stored without asking", "    g_pending = true;\n    ui_confirm(3, import_choice);",
     "    g_pending = true;\n    import_choice(true);"),
    ("import: the same key taken in two slots", "        if (i != d[0] && N_nv.shares[i].present == 1 &&",
     "        if (0 && i != d[0] && N_nv.shares[i].present == 1 &&"),
    ("import: a slot signs with the share of another slot",
     "memcpy(raw + 16, (const void *) N_nv.shares[key - MAX_KEYS].secret, 32);",
     "memcpy(raw + 16, (const void *) N_nv.shares[0].secret, 32);"),
]
if os.environ.get("ONLY"):
    FAULTS = [f for f in FAULTS if os.environ["ONLY"] in f[0]]


def run(whole=False):
    """Builds and runs the suite: (the build worked, failed checks, all passed, exit code).
    With a fault planted, the suite stops at the first check that fails."""
    if subprocess.run(BUILD, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        return False, 0, False, 1
    env = dict(os.environ) if whole else dict(os.environ, STOP_AT_FIRST_FAILURE="1")
    try:
        done = subprocess.run([sys.executable, "tests/run.py"], capture_output=True, text=True, timeout=1800, env=env)
        out, code = done.stdout, done.returncode
    except subprocess.TimeoutExpired as stopped:
        out, code = (stopped.stdout or b"").decode(errors="replace"), -1
    if AFTER:
        subprocess.run(AFTER, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True, out.count("\nFAIL") + out.startswith("FAIL"), "ALL PASSED" in out, code


originals = {path: open(path).read() for path in (SOURCE, KEYS)}
missed = []
try:
    for name, old, new, *where in FAULTS:
        path = where[0] if where else SOURCE
        assert originals[path].count(old) == 1, f"{name}: not applied"
        open(path, "w").write(originals[path].replace(old, new))
        try:
            built, fails, passed, code = run()
        finally:
            open(path, "w").write(originals[path])
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
    for path, content in originals.items():
        open(path, "w").write(content)
built, fails, passed, code = run(whole=True)
print(f"without any fault: {'ALL PASSED' if passed else 'FAILED'}")
sys.exit(bool(missed) or not passed)
