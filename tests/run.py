"""Runs a TEST_BUILD=1 build in the Speculos emulator. No real device, no real key.
With --release, checks instead that a release build has no test command.

- enabling: the screen names the network, and the host cannot swap it during the approval;
- remote-signing API examples: the signature must verify against the published signingRoot;
- EIP-3076 interchange tests, minimal strategy: every accept and refuse must match;
- 2-of-3 threshold: two partial signatures give the group's signature;
- restart: the slashing record survives a power cycle.

Environment: APP (the .elf), SPECULOS (the command), DATA (see fetch.sh), WORK (a scratch folder).
"""
import glob
import hashlib
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import yaml
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, G2_to_signature, signature_to_G2
from py_ecc.optimized_bls12_381 import G1, add, curve_order, multiply

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.abspath(os.environ.get("APP", f"{HERE}/../build/nanos2/bin/app.elf"))
DATA = os.path.abspath(os.environ.get("DATA", f"{HERE}/data"))
WORK = os.path.abspath(os.environ.get("WORK", f"{tempfile.gettempdir()}/validator-signer"))
SPECULOS = os.environ.get("SPECULOS", "speculos")
API = "http://127.0.0.1:5000"

DENIED, BAD_LENGTH, UNKNOWN_COMMAND = 0x6985, 0x6A87, 0x6D00
SLASHABLE, NOT_ENABLED, BAD_KEY = 0xB101, 0xB102, 0xB103
PUBKEY, ENABLE, ATTEST, BLOCK, MARK, IMPORT, RESET, SHARE = 0x06, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26
MAINNET = bytes.fromhex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
HOODI = bytes.fromhex("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
SEPOLIA = bytes.fromhex("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")


class Emulator:
    current = None

    def __init__(self, fresh=True):
        if fresh:
            shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK, exist_ok=True)
        args = [SPECULOS, "--display", "headless", "--model", "nanosp", "--apdu-port", "9999",
                "--api-port", "5000", "--save-nvram"] + ([] if fresh else ["--load-nvram"])
        self.log = open(f"{WORK}/speculos.log", "a")
        self.proc = subprocess.Popen(args + [APP], cwd=WORK, stdout=self.log, stderr=self.log)
        Emulator.current = self
        for _ in range(80):
            time.sleep(0.25)
            if self.proc.poll() is not None:
                raise SystemExit(f"the emulator stopped, see {WORK}/speculos.log")
            try:
                self.sock = socket.create_connection(("127.0.0.1", 9999), timeout=60)
                self.screen()
                return
            except OSError:
                continue
        raise SystemExit("the emulator did not start")

    def stop(self):
        self.sock.close()
        self.proc.terminate()
        self.proc.wait(20)
        Emulator.current = None

    def read(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise SystemExit("the emulator closed the connection")
            out += chunk
        return out

    def write(self, ins, data=b""):
        apdu = bytes([0xE0, ins, 0, 0, len(data)]) + data
        self.sock.sendall(struct.pack(">I", len(apdu)) + apdu)

    def answer(self):
        size = struct.unpack(">I", self.read(4))[0]
        body = self.read(size + 2)
        return body[:-2], struct.unpack(">H", body[-2:])[0]

    def send(self, ins, data=b""):
        self.write(ins, data)
        return self.answer()

    def press(self, which):
        req = urllib.request.Request(f"{API}/button/{which}", method="POST",
                                     data=json.dumps({"action": "press-and-release"}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()

    def screen(self):
        raw = urllib.request.urlopen(f"{API}/events?currentscreenonly=true", timeout=10).read()
        return " / ".join(e["text"] for e in json.loads(raw)["events"])

    def choose(self, choice):
        """Scrolls right until the choice is on screen, then presses both buttons."""
        seen = []
        for _ in range(15):
            time.sleep(0.15)
            seen.append(self.screen())
            if choice in seen[-1]:
                self.press("both")
                return seen
            self.press("right")
        raise SystemExit(f"{choice} never shown: {seen}")

    def enable(self, genesis_root, choice="Approve"):
        self.write(ENABLE, genesis_root)
        seen = self.choose(choice)
        return self.answer()[1], seen

    def pubkey(self, key):
        data, sw = self.send(PUBKEY, struct.pack(">I", key))
        assert sw == 0x9000, hex(sw)
        return data


def unhex(text):
    return bytes.fromhex(text[2:])


def le(v):
    return struct.pack("<Q", int(v))


def header(key, version, root):
    return struct.pack(">I", key) + version + root


def attestation(slot, index, block, source, source_root, target, target_root):
    return le(slot) + le(index) + block + le(source) + source_root + le(target) + target_root


def vote(key, root, source, target):
    zero = bytes(32)
    return header(key, b"\0\0\0\1", root) + attestation(0, 0, secrets.token_bytes(32), source, zero, target, zero)


FAILED = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + (f"  {detail}" if detail else ""), flush=True)
    if not ok:
        FAILED.append(name)


def test_enable(emu):
    root = secrets.token_bytes(32)
    duty = vote(0, root, 0, 1)
    check("refused before being enabled", emu.send(ATTEST, duty)[1] == NOT_ENABLED)
    sw, seen = emu.enable(root, "Reject")
    check("the user can reject", sw == DENIED)
    check("still refused after a reject", emu.send(ATTEST, duty)[1] == NOT_ENABLED)
    sw, seen = emu.enable(root)
    text = "".join(s.split(" / ", 1)[1].replace(" / ", "") for s in seen if s.startswith("Network"))
    check("an unknown network is shown in full", text.lower() == "0x" + root.hex(), text)
    check("the user can enable", sw == 0x9000)
    check("another network is refused", emu.send(ATTEST, vote(0, secrets.token_bytes(32), 0, 1))[1] == NOT_ENABLED)
    check("an unknown key is refused", emu.send(ATTEST, struct.pack(">I", 32) + duty[4:])[1] == BAD_KEY)
    check("a short command is refused", emu.send(ATTEST, duty[:-1])[1] == BAD_LENGTH)
    check("signed without a press", emu.send(ATTEST, duty)[1] == 0x9000)
    check("the same target is refused", emu.send(ATTEST, duty)[1] == SLASHABLE)
    check("a root given by the host is never signed",
          emu.send(0x08, struct.pack(">I", 0) + secrets.token_bytes(32))[1] == UNKNOWN_COMMAND)
    for name, known in (("Mainnet", MAINNET), ("Hoodi", HOODI), ("Sepolia", SEPOLIA)):
        seen = emu.enable(known)[1]
        check(f"{name} is shown by name", f"Network / {name}" in seen, str(seen[1:-1]))


def test_swap_during_approval(emu):
    """The host sends a second network while the user looks at the first one."""
    shown, swapped = secrets.token_bytes(32), secrets.token_bytes(32)
    emu.write(ENABLE, shown)
    time.sleep(0.6)
    second = emu.send(ENABLE, swapped)[1]
    seen = emu.choose("Approve")
    final = emu.answer()[1]
    text = "".join(s.split(" / ", 1)[1].replace(" / ", "") for s in seen if s.startswith("Network"))
    check("a second command during the approval is refused", second != 0x9000 and final == 0x9000, hex(second))
    check("the screen still shows the first network", text.lower() == "0x" + shown.hex())
    check("the network shown is the one enabled", emu.send(ATTEST, vote(9, shown, 0, 1))[1] == 0x9000)
    check("the network swapped in is not", emu.send(ATTEST, vote(9, swapped, 0, 2))[1] == NOT_ENABLED)


def test_api_examples(emu):
    doc = yaml.safe_load(open(f"{DATA}/remote-signing-api/signing/paths/sign.yaml"))
    examples = doc["post"]["requestBody"]["content"]["application/json"]["examples"]
    key = 0
    for name, example in examples.items():
        v = example["value"]
        if v["type"] not in ("ATTESTATION", "BLOCK_V2"):
            continue
        if v["type"] == "BLOCK_V2" and "block_header" not in v["beacon_block"]:
            print(f"skip {name}: a full block, not a header (before Bellatrix)")
            continue
        key += 1
        fork, root = v["fork_info"]["fork"], unhex(v["fork_info"]["genesis_validators_root"])
        assert emu.enable(root)[0] == 0x9000
        if v["type"] == "ATTESTATION":
            a = v["attestation"]
            epoch, ins = int(a["target"]["epoch"]), ATTEST
            body = attestation(a["slot"], a["index"], unhex(a["beacon_block_root"]),
                               a["source"]["epoch"], unhex(a["source"]["root"]),
                               a["target"]["epoch"], unhex(a["target"]["root"]))
        else:
            h = v["beacon_block"]["block_header"]
            epoch, ins = int(h["slot"]) // 32, BLOCK
            body = le(h["slot"]) + le(h["proposer_index"])
            body += unhex(h["parent_root"]) + unhex(h["state_root"]) + unhex(h["body_root"])
        version = unhex(fork["current_version" if epoch >= int(fork["epoch"]) else "previous_version"])
        sig, sw = emu.send(ins, header(key, version, root) + body)
        pk, expected = emu.pubkey(key), unhex(v["signingRoot"])
        good = sw == 0x9000 and bls.Verify(pk, expected, sig)
        bad = sw == 0x9000 and bls.Verify(pk, bytes([expected[0] ^ 1]) + expected[1:], sig)
        check(f"API example {name}", good and not bad, hex(sw))


def test_eip3076(emu):
    cases = signed = refused = 0
    for path in sorted(glob.glob(f"{DATA}/slashing-protection-interchange-tests/tests/**/*.json", recursive=True)):
        case = json.load(open(path))
        root = unhex(case["genesis_validators_root"])
        assert emu.send(RESET)[1] == 0x9000
        assert emu.enable(root)[0] == 0x9000
        keys, errors = {}, []

        def key_of(pubkey):
            return keys.setdefault(pubkey.lower(), len(keys))

        for n, step in enumerate(case["steps"]):
            interchange = step["interchange"]
            file_root = unhex(interchange["metadata"]["genesis_validators_root"])
            # An import starts with the network check, even when it holds no validator.
            imported = emu.send(IMPORT, bytes(30) + file_root)[1] == 0x9000
            for entry in interchange["data"] or []:
                blocks = [int(x["slot"]) for x in entry["signed_blocks"]]
                votes = entry["signed_attestations"]
                data = struct.pack(">I", key_of(entry["pubkey"])) + bytes([bool(blocks), bool(votes)])
                data += le(max(blocks, default=0))
                data += le(max((int(x["source_epoch"]) for x in votes), default=0))
                data += le(max((int(x["target_epoch"]) for x in votes), default=0)) + file_root
                imported &= emu.send(IMPORT, data)[1] == 0x9000
            if imported != step["should_succeed"] and not step["contains_slashable_data"]:
                errors.append(f"step {n}: import {imported}, expected {step['should_succeed']}")
            if not imported:
                break
            for kind, ins in (("blocks", BLOCK), ("attestations", ATTEST)):
                for x in step[kind]:
                    key = key_of(x["pubkey"])
                    if kind == "blocks":
                        duty = header(key, b"\0\0\0\1", root) + le(x["slot"]) + le(0) + secrets.token_bytes(96)
                    else:
                        duty = vote(key, root, x["source_epoch"], x["target_epoch"])
                    ok = {0x9000: True, SLASHABLE: False}[emu.send(ins, duty)[1]]
                    signed, refused = signed + ok, refused + (not ok)
                    if ok != x["should_succeed"]:
                        errors.append(f"step {n} {kind} {x}: {ok}")
        cases += 1
        check(f"EIP-3076 {case['name']}", not errors, "; ".join(errors))
    check("EIP-3076 cases found", cases >= 38, f"{cases} cases, {signed} signed, {refused} refused")


def test_threshold(emu):
    assert emu.send(RESET)[1] == 0x9000
    root = secrets.token_bytes(32)
    assert emu.enable(root)[0] == 0x9000
    secret, slope = (secrets.randbelow(curve_order - 1) + 1 for _ in range(2))
    shares = {i: (secret + slope * i) % curve_order for i in (1, 2, 3)}
    group = G1_to_pubkey(multiply(G1, secret))
    body = attestation(64, 0, b"\2" * 32, 1, b"\3" * 32, 2, b"\4" * 32)

    # The signing root, computed here apart from the device.
    def sha(x, y):
        return hashlib.sha256(x + y).digest()

    def pad(x):
        return x + bytes(32 - len(x))

    zero = bytes(32)
    left = sha(sha(pad(le(64)), pad(le(0))), sha(b"\2" * 32, sha(pad(le(1)), b"\3" * 32)))
    right = sha(sha(sha(pad(le(2)), b"\4" * 32), zero), sha(zero, zero))
    domain = b"\1\0\0\0" + sha(pad(b"\0\0\0\1"), root)[:28]
    message = sha(sha(left, right), domain)

    partial = {}
    for i, share in shares.items():
        sig, sw = emu.send(SHARE, share.to_bytes(32, "big") + header(i, b"\0\0\0\1", root) + body)
        assert sw == 0x9000, hex(sw)
        partial[i] = sig
    for pair in ((1, 2), (1, 3), (2, 3)):
        total = None
        for i in pair:
            j = pair[0] if i == pair[1] else pair[1]
            coefficient = j * pow(j - i, -1, curve_order) % curve_order
            part = multiply(signature_to_G2(partial[i]), coefficient)
            total = part if total is None else add(total, part)
        check(f"threshold 2 of 3, devices {pair}", bls.Verify(group, message, G2_to_signature(total)))
    check("one partial signature is not enough", not bls.Verify(group, message, partial[1]))


def test_restart():
    emu = Emulator()
    root = b"\x42" * 32
    assert emu.enable(root)[0] == 0x9000
    assert emu.send(ATTEST, vote(5, root, 10, 11))[1] == 0x9000
    before = emu.send(MARK, struct.pack(">I", 5))[0]
    emu.stop()
    emu = Emulator(fresh=False)
    after = emu.send(MARK, struct.pack(">I", 5))[0]
    check("the record is kept after a restart", before == after and any(after))
    check("a double vote is refused after a restart", emu.send(ATTEST, vote(5, root, 10, 11))[1] == SLASHABLE)
    check("a surround vote is refused after a restart", emu.send(ATTEST, vote(5, root, 9, 12))[1] == SLASHABLE)
    check("the next vote is signed after a restart", emu.send(ATTEST, vote(5, root, 11, 12))[1] == 0x9000)
    emu.stop()


def test_release():
    """A release build has none of the test commands."""
    emu = Emulator()
    root = secrets.token_bytes(32)
    check("the app answers", emu.send(ATTEST, vote(0, root, 0, 1))[1] == NOT_ENABLED)
    for name, ins, data in (("import", IMPORT, bytes(62)), ("reset", RESET, b""), ("share", SHARE, bytes(200))):
        check(f"no {name} command", emu.send(ins, data)[1] == UNKNOWN_COMMAND)
    emu.stop()


def main():
    if "--release" in sys.argv:
        test_release()
        print(f"\n{'FAILED: ' + ', '.join(FAILED) if FAILED else 'ALL PASSED'}")
        return bool(FAILED)
    emu = Emulator()
    test_enable(emu)
    test_swap_during_approval(emu)
    test_api_examples(emu)
    test_eip3076(emu)
    test_threshold(emu)
    emu.stop()
    test_restart()
    print(f"\n{'FAILED: ' + ', '.join(FAILED) if FAILED else 'ALL PASSED'}")
    return bool(FAILED)


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        if Emulator.current:
            Emulator.current.proc.kill()
