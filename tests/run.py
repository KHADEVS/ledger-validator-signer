"""Runs a TEST_BUILD=1 build in the Speculos emulator. No real device, no real key.
With --release, checks instead that a release build has no test command.

- enabling: the screen names the network, and the host cannot swap it during the approval;
- remote-signing API examples, every duty that has a published signingRoot: the signature must verify against it;
- aggregates of every size, checked against a signing root computed here;
- exits (a press each time) and builder registrations (only for the approved fee recipient);
- EIP-3076 interchange tests, minimal strategy: every accept and refuse must match;
- 2-of-3 threshold: two partial signatures give the group's signature;
- several keys in turn: each signs with its own key, also once the keys are kept in memory;
- import of key shares, encrypted to the device and approved on its screen: what is tampered with
  is refused, the record starts where the import says, and three slots sign as 2 of 3;
- restart: the slashing record and the imported shares survive a power cycle;
- the daemon: the same API examples over HTTP, with the device behind it.

Environment: APP (the .elf), SPECULOS (the command), DATA (see fetch.sh), WORK (a scratch folder),
DAEMON (the daemon's binary; without it, the daemon is not tested), STOP_AT_FIRST_FAILURE (any
value: the suite stops at the first check that fails, which is all the fault runner needs).
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
import urllib.error
import urllib.request

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, G2_to_signature, signature_to_G2
from py_ecc.optimized_bls12_381 import G1, add, curve_order, multiply

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.abspath(os.environ.get("APP", f"{HERE}/../build/nanos2/bin/app.elf"))
DATA = os.path.abspath(os.environ.get("DATA", f"{HERE}/data"))
WORK = os.path.abspath(os.environ.get("WORK", f"{tempfile.gettempdir()}/validator-signer"))
SPECULOS = os.environ.get("SPECULOS", "speculos")

DENIED, BAD_LENGTH, UNKNOWN_COMMAND = 0x6985, 0x6A87, 0x6D00
SLASHABLE, NOT_ENABLED, BAD_KEY, BAD_DUTY, SETTING = 0xB101, 0xB102, 0xB103, 0xB105, 0xB106
PUBKEY, ENABLE, ATTEST, BLOCK, MARK, IMPORT, RESET, SHARE = 0x06, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26
AGGREGATION_SLOT, RANDAO, SYNC_MESSAGE, SYNC_SELECTION = 0x27, 0x28, 0x29, 0x2A
BEGIN, BITS, END, EXIT, SET_FEE, REGISTRATION = 0x2C, 0x2D, 0x2E, 0x30, 0x31, 0x32
GET_IMPORT_KEY, IMPORT_SHARE, BAD_IMPORT = 0x33, 0x34, 0xB107
SLOT = 32  # key numbers from here up are the slots of imported shares
CONTRIBUTION = b"\2"
BEFORE_ELECTRA, ELECTRA, GLOAS = 0, 1, 3  # how an aggregate is laid out and hashed
MAINNET = bytes.fromhex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
HOODI = bytes.fromhex("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
SEPOLIA = bytes.fromhex("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")


class Emulator:
    running = []

    def __init__(self, fresh=True, number=0):
        """`number`: several devices at once, each with its own ports and its own memory."""
        self.work = WORK if number == 0 else f"{WORK}-{number}"
        self.apdu, self.api = 9999 - number, f"http://127.0.0.1:{5000 + number}"
        if fresh:
            shutil.rmtree(self.work, ignore_errors=True)
        os.makedirs(self.work, exist_ok=True)
        args = [SPECULOS, "--display", "headless", "--model", "nanosp", "--apdu-port", str(self.apdu),
                "--api-port", str(5000 + number), "--save-nvram"] + ([] if fresh else ["--load-nvram"])
        self.log = open(f"{self.work}/speculos.log", "a")
        self.proc = subprocess.Popen(args + [APP], cwd=self.work, stdout=self.log, stderr=self.log)
        Emulator.running.append(self)
        for _ in range(80):
            time.sleep(0.25)
            if self.proc.poll() is not None:
                raise SystemExit(f"the emulator stopped, see {self.work}/speculos.log")
            try:
                self.sock = socket.create_connection(("127.0.0.1", self.apdu), timeout=60)
                self.screen()
                return
            except OSError:
                continue
        raise SystemExit("the emulator did not start")

    def stop(self):
        self.sock.close()
        self.proc.terminate()
        self.proc.wait(20)
        if self in Emulator.running:
            Emulator.running.remove(self)

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
        req = urllib.request.Request(f"{self.api}/button/{which}", method="POST",
                                     data=json.dumps({"action": "press-and-release"}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()

    def screen(self):
        raw = urllib.request.urlopen(f"{self.api}/events?currentscreenonly=true", timeout=10).read()
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


def shown(seen, title):
    """A field of an approval, its pages put back together."""
    return "".join(s.split(" / ", 1)[1].replace(" / ", "") for s in seen if s.startswith(title))


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
        if os.environ.get("STOP_AT_FIRST_FAILURE"):
            raise SystemExit(1)


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
    check("an unknown key is refused", emu.send(ATTEST, struct.pack(">I", 36) + duty[4:])[1] == BAD_KEY)
    check("an empty slot is refused", emu.send(ATTEST, struct.pack(">I", SLOT) + duty[4:])[1] == BAD_KEY)
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


# --- signing roots computed here, apart from the device -------------------------------------------

def sha(x, y=b""):
    return hashlib.sha256(x + y).digest()


def pad(x):
    return x + bytes(32 - len(x))


def merkle(chunks, leaves):
    """Root of a tree of `leaves` chunks (a power of two), the missing ones being zero."""
    layer, zero = list(chunks), bytes(32)
    for _ in range((leaves - 1).bit_length()):
        if len(layer) % 2:
            layer.append(zero)
        layer = [sha(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        zero = sha(zero, zero)
    return layer[0] if layer else zero


def progressive(chunks, leaves=1):
    """EIP-7916: a chain of subtrees of 1, 4, 16... chunks."""
    if not chunks:
        return bytes(32)
    return sha(merkle(chunks[:leaves], leaves), progressive(chunks[leaves:], leaves * 4))


def bitlist_root(serialized, limit):
    """`limit` in bits, or None for the progressive bit list of Gloas."""
    top = serialized[-1].bit_length() - 1
    length = 8 * (len(serialized) - 1) + top
    data = (serialized[:-1] + bytes([serialized[-1] & ~(1 << top)]))[:(length + 7) // 8]
    chunks = [pad(data[i:i + 32]) for i in range(0, len(data), 32)]
    return sha(merkle(chunks, limit // 256) if limit else progressive(chunks), length.to_bytes(32, "little"))


def signature_root(sig):
    return merkle([sig[:32], sig[32:64], sig[64:]], 4)


def data_root(body):
    """AttestationData, as sent to the device: slot, index, block root, source, target."""
    return merkle([pad(body[0:8]), pad(body[8:16]), body[16:48],
                   sha(pad(body[48:56]), body[56:88]), sha(pad(body[88:96]), body[96:128])], 8)


def domain(kind, version, root):
    return kind + sha(pad(version), root)[:28]


def aggregate_root(kind, index, body, bits, committee_bits, sig, proof, version, root):
    limit = {BEFORE_ELECTRA: 2048, ELECTRA: 131072, GLOAS: None}[kind]
    fields = [bitlist_root(bits, limit), data_root(body), signature_root(sig)]
    if kind != BEFORE_ELECTRA:
        fields.append(pad(committee_bits))
    # Since Gloas the attestation is a progressive container (EIP-7495), with its four fields active.
    aggregate = sha(progressive(fields), pad(b"\x0f")) if kind == GLOAS else merkle(fields, 4)
    message = merkle([pad(le(index)), aggregate, signature_root(proof)], 4)
    return sha(message, domain(b"\6\0\0\0", version, root))


def registration_root(fee, gas, timestamp, pubkey, genesis_version):
    message = merkle([pad(fee), pad(le(gas)), pad(le(timestamp)), sha(pubkey[:32], pad(pubkey[32:]))], 4)
    return sha(message, domain(b"\0\0\0\1", genesis_version, bytes(32)))


# --- the duties ------------------------------------------------------------------------------------

def send_aggregate(emu, key, version, root, kind, index, body, bits, committee_bits, sig, proof):
    start = header(key, version, root) + bytes([kind])
    start += le(index) + body + struct.pack(">I", len(bits)) + (committee_bits if kind else bytes(8))
    sw = emu.send(BEGIN, start)[1]
    for i in range(0, len(bits), 255):
        if sw == 0x9000:
            sw = emu.send(BITS, bits[i:i + 255])[1]
    return emu.send(END, sig + proof) if sw == 0x9000 else (b"", sw)


def version_of(fork, epoch):
    """The examples write the fork in two styles."""
    name = "current" if epoch >= int(fork["epoch"]) else "previous"
    return unhex(fork.get(f"{name}_version") or fork[f"{name}Version"])


def test_api_examples(emu):
    doc = yaml.safe_load(open(f"{DATA}/remote-signing-api/signing/paths/sign.yaml"))
    examples = doc["post"]["requestBody"]["content"]["application/json"]["examples"]
    key = done = 0
    for name, example in examples.items():
        v = example["value"]
        kind = v["type"]
        if "signingRoot" not in v or "fork_info" not in v:
            continue  # Gloas payload duties have no published root; registration and deposit: see below
        if kind in ("BLOCK", "BLOCK_V2") and "block_header" not in v.get("beacon_block", {}):
            print(f"skip {name}: a full block, not a header (before Bellatrix)")
            continue
        key += 1
        fork, root = v["fork_info"]["fork"], unhex(v["fork_info"]["genesis_validators_root"])
        assert emu.enable(root)[0] == 0x9000
        expected, seen = unhex(v["signingRoot"]), None

        def head(epoch):
            return header(key, version_of(fork, int(epoch)), root)

        if kind == "ATTESTATION":
            a = v["attestation"]
            body = attestation(a["slot"], a["index"], unhex(a["beacon_block_root"]),
                               a["source"]["epoch"], unhex(a["source"]["root"]),
                               a["target"]["epoch"], unhex(a["target"]["root"]))
            sig, sw = emu.send(ATTEST, head(a["target"]["epoch"]) + body)
        elif kind == "BLOCK_V2":
            h = v["beacon_block"]["block_header"]
            body = le(h["slot"]) + le(h["proposer_index"])
            body += unhex(h["parent_root"]) + unhex(h["state_root"]) + unhex(h["body_root"])
            sig, sw = emu.send(BLOCK, head(int(h["slot"]) // 32) + body)
        elif kind == "AGGREGATION_SLOT":
            slot = int(v["aggregation_slot"]["slot"])
            sig, sw = emu.send(AGGREGATION_SLOT, head(slot // 32) + le(slot))
        elif kind == "RANDAO_REVEAL":
            epoch = int(v["randao_reveal"]["epoch"])
            sig, sw = emu.send(RANDAO, head(epoch) + le(epoch))
        elif kind == "SYNC_COMMITTEE_MESSAGE":
            m = v["sync_committee_message"]
            sig, sw = emu.send(SYNC_MESSAGE, head(int(m["slot"]) // 32) + unhex(m["beacon_block_root"]))
        elif kind == "SYNC_COMMITTEE_SELECTION_PROOF":
            m = v["sync_aggregator_selection_data"]
            sig, sw = emu.send(SYNC_SELECTION, head(int(m["slot"]) // 32) + le(m["slot"]) + le(m["subcommittee_index"]))
        elif kind == "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF":
            m = v["contribution_and_proof"]
            c = m["contribution"]
            bits = unhex(c["aggregation_bits"])  # the example uses a small test network: fewer bits, same chunk
            start = head(int(c["slot"]) // 32) + CONTRIBUTION + le(m["aggregator_index"]) + le(c["slot"])
            start += unhex(c["beacon_block_root"]) + le(c["subcommittee_index"]) + bits + bytes(16 - len(bits))
            assert emu.send(BEGIN, start)[1] == 0x9000
            sig, sw = emu.send(END, unhex(c["signature"]) + unhex(m["selection_proof"]))
        elif kind in ("AGGREGATE_AND_PROOF", "AGGREGATE_AND_PROOF_V2"):
            m = v["aggregate_and_proof"]
            layout = {"ELECTRA": ELECTRA, "FULU": ELECTRA, "GLOAS": GLOAS}.get(m.get("version"), BEFORE_ELECTRA)
            m = m.get("data", m)
            g, a = m["aggregate"], m["aggregate"]["data"]
            body = attestation(a["slot"], a["index"], unhex(a["beacon_block_root"]),
                               a["source"]["epoch"], unhex(a["source"]["root"]),
                               a["target"]["epoch"], unhex(a["target"]["root"]))
            version = version_of(fork, int(a["slot"]) // 32)
            parts = (layout, int(m["aggregator_index"]), body, unhex(g["aggregation_bits"]),
                     unhex(g.get("committee_bits", "0x")), unhex(g["signature"]), unhex(m["selection_proof"]))
            check(f"the root computed here for {name} is the published one",
                  aggregate_root(*parts, version, root) == expected)
            sig, sw = send_aggregate(emu, key, version, root, *parts)
        elif kind == "VOLUNTARY_EXIT":
            m = v["voluntary_exit"]
            duty = head(m["epoch"]) + le(m["epoch"]) + le(m["validator_index"])
            emu.write(EXIT, duty)
            check("an exit can be rejected on the device", (emu.choose("Reject"), emu.answer()[1])[1] == DENIED)
            emu.write(EXIT, duty)
            seen = emu.choose("Approve")
            sig, sw = emu.answer()
            check("the exit screen shows the validator and the epoch",
                  shown(seen, "Validator") == m["validator_index"] and shown(seen, "Epoch") == m["epoch"], str(seen))
        else:
            check(f"API example {name} has a test", False, kind)
            continue
        pk = emu.pubkey(key)
        good = sw == 0x9000 and bls.Verify(pk, expected, sig)
        bad = sw == 0x9000 and bls.Verify(pk, bytes([expected[0] ^ 1]) + expected[1:], sig)
        check(f"API example {name}", good and not bad, hex(sw))
        done += 1
    check("API examples found", done >= 22, f"{done} examples")


def test_aggregates(emu):
    """Bit lists of every awkward size, in several commands, against the root computed here."""
    root, version = secrets.token_bytes(32), b"\0\0\0\7"
    assert emu.enable(root)[0] == 0x9000
    key, pk = 30, emu.pubkey(30)
    body = attestation(1000, 3, b"\5" * 32, 30, b"\6" * 32, 31, b"\7" * 32)
    sig, proof = secrets.token_bytes(96), secrets.token_bytes(96)
    # For Gloas, the sizes sit around the ends of the subtrees: 1, 5, 21, 85 and 341 chunks of 256 bits.
    for kind, name, sizes in (
            (BEFORE_ELECTRA, "before Electra", (0, 1, 7, 8, 9, 255, 256, 257, 511, 2040, 2047, 2048)),
            (ELECTRA, "since Electra", (0, 1, 256, 2048, 2049, 65535, 65536, 65537, 131071, 131072)),
            (GLOAS, "since Gloas", (0, 1, 255, 256, 257, 1279, 1280, 1281, 5376, 5377, 21760, 21761, 87296, 87297,
                                    131071, 131072))):
        wrong = []
        for bits in sizes:
            value = secrets.randbits(bits) | (1 << bits)  # the bit that ends the list
            serialized = value.to_bytes(bits // 8 + 1, "little")
            committee = secrets.token_bytes(8)
            parts = (kind, 77, body, serialized, committee, sig, proof)
            out, sw = send_aggregate(emu, key, version, root, *parts)
            if sw != 0x9000 or not bls.Verify(pk, aggregate_root(*parts, version, root), out):
                wrong.append(bits)
        check(f"aggregates {name}, {len(sizes)} sizes of bit list", not wrong, f"wrong for {wrong} bits" if wrong else "")

    def start(electra, length):
        data = header(key, version, root) + bytes([ELECTRA if electra else BEFORE_ELECTRA])
        return emu.send(BEGIN, data + le(77) + body + struct.pack(">I", length) + bytes(8))[1]

    check("bits without a start are refused", emu.send(BITS, b"\1")[1] == BAD_DUTY)
    check("an end without a start is refused", emu.send(END, sig + proof)[1] == BAD_DUTY)
    check("an empty bit list is refused", start(False, 0) == BAD_DUTY)
    check("a bit list longer than the limit is refused", start(False, 258) == BAD_DUTY and start(True, 16386) == BAD_DUTY)
    assert start(False, 4) == 0x9000
    check("an end before all the bits is refused",
          emu.send(BITS, b"\xff\xff")[1] == 0x9000 and emu.send(END, sig + proof)[1] == BAD_DUTY)
    assert start(False, 2) == 0x9000
    check("more bits than announced are refused", emu.send(BITS, b"\1\1\1")[1] == BAD_DUTY)
    assert start(False, 2) == 0x9000
    check("a list without its end bit is refused", emu.send(BITS, b"\xff\0")[1] == BAD_DUTY)
    assert start(False, 257) == 0x9000
    check("one bit over the limit is refused",
          emu.send(BITS, bytes(255))[1] == 0x9000 and emu.send(BITS, b"\0\2")[1] == BAD_DUTY)
    assert start(False, 2) == 0x9000 and emu.send(BITS, b"\xff\1")[1] == 0x9000
    other = secrets.token_bytes(32)
    assert emu.enable(other)[0] == 0x9000
    check("an aggregate started for another network is not finished", emu.send(END, sig + proof)[1] == NOT_ENABLED)


def test_registration(emu):
    doc = yaml.safe_load(open(f"{DATA}/remote-signing-api/signing/paths/sign.yaml"))
    v = doc["post"]["requestBody"]["content"]["application/json"]["examples"]["VALIDATOR_REGISTRATION"]["value"]
    r = v["validator_registration"]
    fee, gas, stamp = unhex(r["fee_recipient"]), int(r["gas_limit"]), int(r["timestamp"])
    genesis = [x for x in (bytes(4), b"\0\0\0\1")
               if registration_root(fee, gas, stamp, unhex(r["pubkey"]), x) == unhex(v["signingRoot"])]
    check("the registration root computed here is the published one", len(genesis) == 1)
    genesis = genesis[0] if genesis else bytes(4)

    root = secrets.token_bytes(32)
    assert emu.send(RESET)[1] == 0x9000 and emu.enable(root)[0] == 0x9000
    key, pk = 3, emu.pubkey(3)
    duty = header(key, genesis, root) + fee + le(gas) + le(stamp)
    emu.write(SET_FEE, fee + le(gas))
    check("the fee recipient can be rejected", (emu.choose("Reject"), emu.answer()[1])[1] == DENIED)
    emu.write(SET_FEE, fee + le(gas))
    seen = emu.choose("Approve")
    check("the screen shows the fee recipient and the gas limit",
          emu.answer()[1] == 0x9000 and shown(seen, "Recipient").lower() == "0x" + fee.hex()
          and shown(seen, "Gas limit") == str(gas), str(seen))
    sig, sw = emu.send(REGISTRATION, duty)
    expected = registration_root(fee, gas, stamp, pk, genesis)
    check("a registration for the approved recipient is signed, with the device's own key in it",
          sw == 0x9000 and bls.Verify(pk, expected, sig))
    thief = header(key, genesis, root) + secrets.token_bytes(20) + le(gas) + le(stamp)
    check("another fee recipient is refused", emu.send(REGISTRATION, thief)[1] == SETTING)
    check("another gas limit is refused",
          emu.send(REGISTRATION, header(key, genesis, root) + fee + le(gas + 1) + le(stamp))[1] == SETTING)
    check("another network is refused",
          emu.send(REGISTRATION, header(key, genesis, secrets.token_bytes(32)) + fee + le(gas) + le(stamp))[1] == NOT_ENABLED)


def test_before_approval():
    """A device that was never set up signs nothing."""
    emu = Emulator()
    root = secrets.token_bytes(32)
    head = header(0, b"\0\0\0\1", root)
    for name, ins, body in (("aggregation slot", AGGREGATION_SLOT, le(1)), ("RANDAO", RANDAO, le(1)),
                            ("sync message", SYNC_MESSAGE, bytes(32)), ("sync selection", SYNC_SELECTION, bytes(16)),
                            ("exit", EXIT, bytes(16)), ("aggregate", BEGIN, bytes([GLOAS]) + bytes(148)),
                            ("contribution", BEGIN, CONTRIBUTION + bytes(72))):
        check(f"{name}: refused before a network is enabled", emu.send(ins, head + body)[1] == NOT_ENABLED)
    assert emu.enable(root)[0] == 0x9000
    check("registration: refused before a fee recipient is approved",
          emu.send(REGISTRATION, head + bytes(36))[1] == SETTING)
    emu.stop()


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


def combine(partial, pair):
    """The group's signature from two partial ones (Lagrange at zero)."""
    total = None
    for i in pair:
        j = pair[0] if i == pair[1] else pair[1]
        part = multiply(signature_to_G2(partial[i]), j * pow(j - i, -1, curve_order) % curve_order)
        total = part if total is None else add(total, part)
    return G2_to_signature(total)


def test_keys(emu):
    """Keys used in turn: each signature is made with the key asked for."""
    assert emu.send(RESET)[1] == 0x9000
    root = secrets.token_bytes(32)
    assert emu.enable(root)[0] == 0x9000
    wrong = []
    for n, key in enumerate((0, 1, 31, 0, 31, 1, 17, 0)):
        body = attestation(n, 0, secrets.token_bytes(32), n, bytes(32), n + 1, bytes(32))
        sig, sw = emu.send(ATTEST, header(key, b"\0\0\0\1", root) + body)
        message = sha(data_root(body), domain(b"\1\0\0\0", b"\0\0\0\1", root))
        if sw != 0x9000 or not bls.Verify(emu.pubkey(key), message, sig):
            wrong.append(key)
    check("keys used in turn each sign with their own key", not wrong, str(wrong))
    check("the keys are all different", len({emu.pubkey(k) for k in (0, 1, 17, 31)}) == 4)


LABEL = b"ledger-validator-signer share import v1"


def plain(text):
    """A text of the screen without its spaces: a line may end where a space was."""
    return text.replace(" ", "")


def seal_share(device_pub, slot, index, group, share, source=0, target=0, block=0, flags=0):
    """What is sent to a device to import one share: the header in clear, then the share sealed to
    the device's key (ECDH on P-256, HKDF-SHA256, AES-256-GCM over the share, header authenticated)."""
    head = bytes([slot, index]) + group + le(source) + le(target) + le(block) + bytes([flags])
    sender = ec.generate_private_key(ec.SECP256R1())
    sender_pub = sender.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
    shared = sender.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=LABEL + sender_pub + device_pub).derive(shared)
    nonce = secrets.token_bytes(12)
    raw = share if isinstance(share, bytes) else share.to_bytes(32, "big")
    return head + sender_pub + nonce + AESGCM(key).encrypt(nonce, raw, head)


def test_import():
    """An existing key, split in three shares, each imported encrypted into a slot."""
    emu = Emulator()
    root = secrets.token_bytes(32)
    assert emu.enable(root)[0] == 0x9000
    check("import: refused before the device has shown its import key",
          emu.send(IMPORT_SHARE, bytes(200))[1] == BAD_IMPORT)

    emu.write(GET_IMPORT_KEY)
    seen = emu.choose("Approve")
    device_pub, sw = emu.answer()
    text = shown(seen, "Key check")
    check("import key: the screen shows its check",
          sw == 0x9000 and len(device_pub) == 65 and text.lower() == hashlib.sha256(device_pub).hexdigest()[:16], text)
    emu.write(GET_IMPORT_KEY)
    emu.choose("Reject")
    check("import key: the user can refuse to give it", emu.answer()[1] == DENIED)
    emu.write(GET_IMPORT_KEY)
    emu.choose("Approve")
    check("import key: the same key every time", emu.answer()[0] == device_pub)

    secret, slope = (secrets.randbelow(curve_order - 1) + 1 for _ in range(2))
    shares = {i: (secret + slope * i) % curve_order for i in (1, 2, 3)}
    group = G1_to_pubkey(multiply(G1, secret))
    before = dict(source=5, target=6, block=100, flags=3)
    good = seal_share(device_pub, 0, 1, group, shares[1], **before)

    def flipped(blob, at):
        return blob[:at] + bytes([blob[at] ^ 1]) + blob[at + 1:]

    other_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    refused = {
        "another slot than the one sealed": flipped(good, 0),
        "another share number": flipped(good, 1),
        "another group key": flipped(good, 20),
        "an earlier starting point": flipped(good, 58),
        "other flags": good[:74] + b"\1" + good[75:],
        "a changed sender key": good[:75] + other_key + good[140:],
        "a changed nonce": flipped(good, 141),
        "a changed share": flipped(good, 160),
        "a changed tag": flipped(good, 199),
        "a share sealed to another device": seal_share(other_key, 0, 1, group, shares[1], **before),
        "a share of zero": seal_share(device_pub, 0, 1, group, bytes(32), **before),
        "a share above the order of the group": seal_share(device_pub, 0, 1, group, curve_order, **before),
        "a slot that does not exist": seal_share(device_pub, 4, 1, group, shares[1], **before),
        "a share number of zero": seal_share(device_pub, 0, 0, group, shares[1], **before),
        "a starting point too large to show": seal_share(device_pub, 0, 1, group, shares[1], source=10 ** 12, flags=1),
    }
    for name, blob in refused.items():
        check(f"import refused: {name}", emu.send(IMPORT_SHARE, blob)[1] == BAD_IMPORT)
    check("import refused: a short message", emu.send(IMPORT_SHARE, good[:-1])[1] == BAD_LENGTH)
    check("import: nothing was stored by the refused ones", emu.send(ATTEST, vote(SLOT, root, 10, 11))[1] == BAD_KEY)

    emu.write(IMPORT_SHARE, good)
    emu.choose("Reject")
    check("import: the user can reject", emu.answer()[1] == DENIED)
    check("import: nothing is stored after a reject", emu.send(ATTEST, vote(SLOT, root, 10, 11))[1] == BAD_KEY)

    for slot, index in ((0, 1), (1, 2), (2, 3)):
        emu.write(IMPORT_SHARE, seal_share(device_pub, slot, index, group, shares[index], **before))
        seen = emu.choose("Approve")
        sw = emu.answer()[1]
        key_text = shown(seen, "Group key").lower()
        ok = (sw == 0x9000 and plain(shown(seen, "Slot")) == f"{slot},share{index}"
              and key_text == f"0x{group[:6].hex()}..{group[-6:].hex()}"
              and plain(shown(seen, "Not before")) == "source5,target6,slot100")
        check(f"import: share {index} into slot {slot}, shown on the screen", ok, str(seen[1:-1]))
        check(f"import: slot {slot} gives the group key and its share number",
              emu.send(PUBKEY, struct.pack(">I", SLOT + slot))[0] == group + bytes([index]))
    check("import: the same share into another slot is refused",
          emu.send(IMPORT_SHARE, seal_share(device_pub, 3, 1, group, shares[1]))[1] == BAD_IMPORT)

    check("import: a vote at the starting point is refused", emu.send(ATTEST, vote(SLOT, root, 5, 6))[1] == SLASHABLE)
    check("import: a vote from before the starting point is refused",
          emu.send(ATTEST, vote(SLOT, root, 4, 7))[1] == SLASHABLE)
    old_block = header(SLOT, b"\0\0\0\1", root) + le(100) + le(0) + secrets.token_bytes(96)
    check("import: a block at the starting point is refused", emu.send(BLOCK, old_block)[1] == SLASHABLE)

    body = attestation(64, 0, b"\2" * 32, 5, b"\3" * 32, 7, b"\4" * 32)
    message = sha(data_root(body), domain(b"\1\0\0\0", b"\0\0\0\1", root))
    partial = {}
    for slot, index in ((0, 1), (1, 2), (2, 3)):
        partial[index], sw = emu.send(ATTEST, header(SLOT + slot, b"\0\0\0\1", root) + body)
        assert sw == 0x9000, hex(sw)
    for pair in ((1, 2), (1, 3), (2, 3)):
        check(f"import: slots of shares {pair} sign a vote for the group key",
              bls.Verify(group, message, combine(partial, pair)))
    check("import: one slot alone does not", not bls.Verify(group, message, partial[1]))
    check("import: each slot has its own record",
          emu.send(ATTEST, header(SLOT, b"\0\0\0\1", root) + body)[1] == SLASHABLE)

    # Another duty, to see that a slot signs everything a key signs: the block header.
    fields = [le(101), le(7), b"\5" * 32, b"\6" * 32, b"\7" * 32]
    block_root = sha(merkle([pad(f) for f in fields], 8), domain(b"\0\0\0\0", b"\0\0\0\1", root))
    for slot, index in ((0, 1), (2, 3)):
        partial[index], sw = emu.send(BLOCK, header(SLOT + slot, b"\0\0\0\1", root) + b"".join(fields))
        assert sw == 0x9000, hex(sw)
    check("import: two slots sign a block for the group key", bls.Verify(group, block_root, combine(partial, (1, 3))))
    epoch = le(9)
    randao = sha(pad(epoch), domain(b"\2\0\0\0", b"\0\0\0\1", root))
    for slot, index in ((1, 2), (2, 3)):
        partial[index], sw = emu.send(RANDAO, header(SLOT + slot, b"\0\0\0\1", root) + epoch)
        assert sw == 0x9000, hex(sw)
    check("import: two slots sign a RANDAO reveal for the group key",
          bls.Verify(group, randao, combine(partial, (2, 3))))

    # The same share again, with an earlier starting point: the record does not go back.
    emu.write(IMPORT_SHARE, seal_share(device_pub, 0, 1, group, shares[1], source=0, target=1, block=1, flags=3))
    seen = emu.choose("Approve")
    check("import again: accepted, and the screen keeps the later point",
          emu.answer()[1] == 0x9000 and plain(shown(seen, "Not before")) == "source5,target7,slot101", str(seen[1:-1]))
    check("import again: the record did not go back", emu.send(ATTEST, vote(SLOT, root, 5, 7))[1] == SLASHABLE)

    # Replacing a device: the key is split again and every holder takes its new share. A share of
    # the old split is then of no use, and a holder that stays keeps its record.
    new_slope = secrets.randbelow(curve_order - 1) + 1
    new_shares = {i: (secret + new_slope * i) % curve_order for i in (1, 2, 3)}
    for slot, index in ((0, 1), (1, 2), (2, 3)):
        emu.write(IMPORT_SHARE, seal_share(device_pub, slot, index, group, new_shares[index]))
        emu.choose("Approve")
        assert emu.answer()[1] == 0x9000
    check("new split: the record did not go back", emu.send(ATTEST, vote(SLOT, root, 5, 7))[1] == SLASHABLE)
    body = attestation(96, 0, b"\2" * 32, 7, b"\3" * 32, 9, b"\4" * 32)
    message = sha(data_root(body), domain(b"\1\0\0\0", b"\0\0\0\1", root))
    fresh = {}
    for slot, index in ((0, 1), (1, 2), (2, 3)):
        fresh[index], sw = emu.send(ATTEST, header(SLOT + slot, b"\0\0\0\1", root) + body)
        assert sw == 0x9000, hex(sw)
    check("new split: the new shares sign for the same key",
          all(bls.Verify(group, message, combine(fresh, pair)) for pair in ((1, 2), (1, 3), (2, 3))))
    left_out = {1: fresh[1], 3: bls.Sign(shares[3], message)}
    check("new split: a share of the old split does not combine with a new one",
          not bls.Verify(group, message, combine(left_out, (1, 3))))

    emu.stop()
    emu = Emulator(fresh=False)
    check("import: the share is kept after a restart",
          emu.send(PUBKEY, struct.pack(">I", SLOT + 1))[0] == group + bytes([2]))
    check("import: its record too", emu.send(ATTEST, vote(SLOT + 1, root, 7, 9))[1] == SLASHABLE)
    check("import: and it signs the next vote", emu.send(ATTEST, vote(SLOT + 1, root, 9, 10))[1] == 0x9000)
    emu.stop()


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


def http(method, url, body=None, accept=None):
    headers = {"Content-Type": "application/json"}
    if accept:
        headers["Accept"] = accept
    data = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method, data=data, headers=headers), timeout=120) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_daemon():
    """The API examples again, as HTTP requests to the daemon, which holds the device."""
    exe = os.environ.get("DAEMON")
    if not exe:
        print("skip the daemon: DAEMON is not set")
        return
    doc = yaml.safe_load(open(f"{DATA}/remote-signing-api/signing/paths/sign.yaml"))
    examples = doc["post"]["requestBody"]["content"]["application/json"]["examples"]
    roots = {e["value"]["fork_info"]["genesis_validators_root"] for e in examples.values() if "fork_info" in e["value"]}
    assert len(roots) == 1, roots
    root = unhex(roots.pop())
    r = examples["VALIDATOR_REGISTRATION"]["value"]["validator_registration"]
    fee, gas, stamp = unhex(r["fee_recipient"]), int(r["gas_limit"]), int(r["timestamp"])
    published = unhex(examples["VALIDATOR_REGISTRATION"]["value"]["signingRoot"])
    genesis = next(x for x in (bytes(4), b"\0\0\0\1") if registration_root(fee, gas, stamp, unhex(r["pubkey"]), x) == published)

    emu = Emulator()
    assert emu.enable(root)[0] == 0x9000
    emu.write(SET_FEE, fee + le(gas))
    emu.choose("Approve")
    assert emu.answer()[1] == 0x9000
    emu.sock.close()  # the daemon takes the device from here

    url = "http://127.0.0.1:9100"
    log = open(f"{WORK}/daemon.log", "w")
    daemon = subprocess.Popen([exe, "--device", "127.0.0.1:9999", "--listen", "127.0.0.1:9100", "--keys", "32",
                               "--genesis-fork-version", "0x" + genesis.hex(),
                               "--genesis-validators-root", "0x" + root.hex()], stdout=log, stderr=log)
    try:
        for _ in range(200):
            time.sleep(0.25)
            if daemon.poll() is not None:
                raise SystemExit(f"the daemon stopped, see {WORK}/daemon.log")
            try:
                if http("GET", url + "/upcheck")[0] == 200:
                    break
            except OSError:
                continue
        else:
            raise SystemExit("the daemon did not start")
        keys = json.loads(http("GET", url + "/api/v1/eth2/publicKeys")[1])
        check("daemon: lists the device's keys", len(keys) == 32 and len(set(keys)) == 32)
        signed, used = 0, {}
        for n, (name, example) in enumerate(examples.items()):
            v = dict(example["value"])
            key = used[name] = keys[n]
            pk, expected = unhex(key), unhex(v["signingRoot"]) if "signingRoot" in v else None
            header_only = v["type"] not in ("BLOCK", "BLOCK_V2") or "block_header" in v.get("beacon_block", {})
            signable = "fork_info" in v and expected is not None and header_only
            if v["type"] == "VALIDATOR_REGISTRATION":
                v["validator_registration"] = dict(r, pubkey=key)
                expected, signable = registration_root(fee, gas, stamp, pk, genesis), True
            target = f"{url}/api/v1/eth2/sign/{key}"
            if v["type"] == "VOLUNTARY_EXIT":
                answer = []
                thread = threading.Thread(target=lambda: answer.append(http("POST", target, v, "application/json")))
                thread.start()
                time.sleep(0.5)
                emu.choose("Approve")
                thread.join(120)
                status, body = answer[0]
            else:
                status, body = http("POST", target, v, "application/json")
            if not signable:
                check(f"daemon: {name} is refused as a bad request", status == 400, f"{status} {body[:70]}")
                continue
            ok = status == 200 and bls.Verify(pk, expected, unhex(json.loads(body)["signature"]))
            check(f"daemon: {name}", ok, "" if ok else f"{status} {body[:80]}")
            signed += ok
        check("daemon: examples signed", signed >= 23, f"{signed} examples")
        again = examples["ATTESTATION"]["value"]
        status, body = http("POST", f"{url}/api/v1/eth2/sign/{used['ATTESTATION']}", again)
        check("daemon: the same attestation again is 412", status == 412, f"{status} {body[:60]}")
        status, body = http("POST", f"{url}/api/v1/eth2/sign/{used['RANDAO_REVEAL']}", examples["RANDAO_REVEAL"]["value"])
        check("daemon: plain text when JSON is not asked for", status == 200 and body.startswith("0x") and len(body) == 194)
        check("daemon: an unknown key is 404", http("POST", f"{url}/api/v1/eth2/sign/0x{'ab' * 48}", again)[0] == 404)
        check("daemon: a body that is not JSON is 400", http("POST", f"{url}/api/v1/eth2/sign/{keys[0]}", b"{")[0] == 400)
        other = dict(again, fork_info=dict(again["fork_info"], genesis_validators_root="0x" + "11" * 32))
        check("daemon: another network is not signed", http("POST", f"{url}/api/v1/eth2/sign/{keys[31]}", other)[0] == 500)
    finally:
        daemon.terminate()
        daemon.wait(20)
        emu.stop()


def start_daemon(exe, arguments, url, log_name):
    log = open(f"{WORK}/{log_name}", "w")
    daemon = subprocess.Popen([exe] + arguments, stdout=log, stderr=log)
    for _ in range(200):
        time.sleep(0.25)
        if daemon.poll() is not None:
            raise SystemExit(f"a daemon stopped, see {WORK}/{log_name}")
        try:
            if http("GET", url + "/upcheck")[0] == 200:
                return daemon
        except OSError:
            continue
    daemon.kill()
    raise SystemExit("a daemon did not start")


def test_combiner():
    """Three devices with one share each, a daemon in front of each, and one more daemon that
    asks the three and gives the validator client the key's signature."""
    exe = os.environ.get("DAEMON")
    if not exe:
        print("skip the combiner: DAEMON is not set")
        return
    doc = yaml.safe_load(open(f"{DATA}/remote-signing-api/signing/paths/sign.yaml"))
    examples = {name: e["value"] for name, e in doc["post"]["requestBody"]["content"]["application/json"]["examples"].items()}
    root = unhex(examples["ATTESTATION"]["fork_info"]["genesis_validators_root"])

    def split():
        secret, slope = (secrets.randbelow(curve_order - 1) + 1 for _ in range(2))
        return G1_to_pubkey(multiply(G1, secret)), {i: (secret + slope * i) % curve_order for i in (1, 2, 3)}

    group, shares = split()
    # A second key, of which the first device is given a share that is not one.
    spoiled, spoiled_shares = split()
    spoiled_shares[1] = secrets.randbelow(curve_order - 1) + 1
    key, spoiled_key = "0x" + group.hex(), "0x" + spoiled.hex()
    emus, daemons = [], []
    signers = [f"http://127.0.0.1:{9101 + n}" for n in range(3)]
    front = "http://127.0.0.1:9100"

    def signed(name, to=key, public=group):
        status, body = http("POST", f"{front}/api/v1/eth2/sign/{to}", examples[name], "application/json")
        ok = status == 200 and bls.Verify(public, unhex(examples[name]["signingRoot"]), unhex(json.loads(body)["signature"]))
        return ok, f"{status} {body[:80]}"

    def arguments(n):
        return ["--device", f"127.0.0.1:{emus[n].apdu}", "--listen", f"127.0.0.1:{9101 + n}", "--keys", "0"]

    def stop(n):
        daemons[n].terminate()
        daemons[n].wait(20)

    def start(n):
        daemons[n] = start_daemon(exe, arguments(n), signers[n], f"signer-{n}.log")

    def vote_request(source, target, block=b"\x11" * 32):
        """An attestation with these epochs, in the form of the API, with its signing root."""
        request = json.loads(json.dumps(examples["ATTESTATION"]))
        data = request["attestation"]
        data["slot"], data["beacon_block_root"] = str(32 * target), "0x" + block.hex()
        data["source"]["epoch"], data["target"]["epoch"] = str(source), str(target)
        body = attestation(32 * target, 0, block, source, unhex(data["source"]["root"]),
                           target, unhex(data["target"]["root"]))
        version = version_of(request["fork_info"]["fork"], target)
        request["signingRoot"] = "0x" + sha(data_root(body), domain(b"\1\0\0\0", version, root)).hex()
        return request

    def vote_signed(request):
        status, body = http("POST", f"{front}/api/v1/eth2/sign/{key}", request, "application/json")
        ok = status == 200 and bls.Verify(group, unhex(request["signingRoot"]), unhex(json.loads(body)["signature"]))
        return ok, f"{status} {body[:80]}"

    def vote_refused(request):
        status, body = http("POST", f"{front}/api/v1/eth2/sign/{key}", request, "application/json")
        return status == 412, f"{status} {body[:80]}"

    try:
        for n in range(3):
            emu = Emulator(number=n)
            emus.append(emu)
            assert emu.enable(root)[0] == 0x9000
            emu.write(GET_IMPORT_KEY)
            emu.choose("Approve")
            device_pub = emu.answer()[0]
            for slot, (public, parts) in enumerate(((group, shares), (spoiled, spoiled_shares))):
                emu.write(IMPORT_SHARE, seal_share(device_pub, slot, n + 1, public, parts[n + 1]))
                emu.choose("Approve")
                assert emu.answer()[1] == 0x9000
            emu.sock.close()  # its daemon takes the device from here
            daemons.append(start_daemon(exe, arguments(n), signers[n], f"signer-{n}.log"))
        daemons.append(start_daemon(exe, ["--combine", ",".join(signers), "--listen", "127.0.0.1:9100"], front, "combiner.log"))

        check("combiner: a signer with shares offers no key of its own",
              json.loads(http("GET", signers[0] + "/api/v1/eth2/publicKeys")[1]) == [])
        held = json.loads(http("GET", signers[1] + "/api/v1/shares")[1])
        check("combiner: a signer lists its shares", held == [{"pubkey": key, "share": 2}, {"pubkey": spoiled_key, "share": 2}], str(held))
        offered = json.loads(http("GET", front + "/api/v1/eth2/publicKeys")[1])
        check("combiner: offers the keys that enough signers hold", sorted(offered) == sorted([key, spoiled_key]), str(offered))
        check("combiner: a signer alone gives a partial signature, not the key's",
              not bls.Verify(group, unhex(examples["AGGREGATION_SLOT"]["signingRoot"]), unhex(json.loads(
                  http("POST", f"{signers[0]}/partial/v1/eth2/sign/{key}", examples["AGGREGATION_SLOT"], "application/json")[1])["signature"])))

        check("combiner: an attestation is signed for the key", *signed("ATTESTATION"))
        status, body = http("POST", f"{front}/api/v1/eth2/sign/{key}", examples["ATTESTATION"])
        check("combiner: the same attestation again is 412", status == 412, f"{status} {body[:60]}")
        check("combiner: a RANDAO reveal is signed for the key", *signed("RANDAO_REVEAL"))
        check("combiner: an unknown key is 404",
              http("POST", f"{front}/api/v1/eth2/sign/0x{'ab' * 48}", examples["RANDAO_REVEAL"])[0] == 404)
        check("combiner: a wrong share is left out, the two others sign", *signed("RANDAO_REVEAL", spoiled_key, spoiled))

        # An exit waits for a press on each device.
        answer = []
        thread = threading.Thread(target=lambda: answer.append(signed("VOLUNTARY_EXIT")))
        thread.start()
        time.sleep(1.0)
        for emu in emus:
            emu.choose("Approve")
        thread.join(200)
        check("combiner: an exit is signed once approved on the devices", *(answer[0] if answer else (False, "no answer")))

        stop(2)
        check("combiner: with one signer down, two still sign", *signed("SYNC_COMMITTEE_MESSAGE"))

        # A takeover. Two devices sign a vote while the third is down. Then the third is back and
        # one of the two is gone: the new pair has one device in common with the old one, and that
        # device holds the vote in its own record. Nothing is handed over between devices.
        check("takeover: two devices sign a vote while the third is down", *vote_signed(vote_request(10, 20)))
        start(2)
        stop(0)
        check("takeover: the other pair is refused a vote that surrounds it", *vote_refused(vote_request(9, 21)))
        alone = http("POST", f"{signers[2]}/partial/v1/eth2/sign/{key}", vote_request(9, 22), "application/json")[0]
        check("takeover: the device that was down would sign such a vote, the common one refused", alone == 200, str(alone))
        start(0)
        stop(2)
        check("takeover: the first pair signs a later vote", *vote_signed(vote_request(30, 40)))
        start(2)
        stop(0)
        check("takeover: the other pair is refused a second vote for the same target",
              *vote_refused(vote_request(30, 40, block=b"\x22" * 32)))
        check("takeover: and it signs the vote after that", *vote_signed(vote_request(31, 41)))

        stop(1)
        status, body = http("POST", f"{front}/api/v1/eth2/sign/{key}", examples["SYNC_COMMITTEE_SELECTION_PROOF"], "application/json")
        check("combiner: with two signers down, nothing is signed", status == 500, f"{status} {body[:90]}")
    finally:
        for daemon in daemons:
            if daemon.poll() is None:
                daemon.terminate()
                daemon.wait(20)
        for emu in emus:
            emu.stop()


def test_release():
    """A release build has none of the test commands, and it takes a share only the sealed way."""
    emu = Emulator()
    root = secrets.token_bytes(32)
    check("the app answers", emu.send(ATTEST, vote(0, root, 0, 1))[1] == NOT_ENABLED)
    for name, ins, data in (("import", IMPORT, bytes(62)), ("reset", RESET, b""), ("share", SHARE, bytes(200))):
        check(f"no {name} command", emu.send(ins, data)[1] == UNKNOWN_COMMAND)
    emu.write(GET_IMPORT_KEY)
    emu.choose("Approve")
    device_pub, sw = emu.answer()
    check("the key to seal a share to is given", sw == 0x9000 and len(device_pub) == 65)
    secret = secrets.randbelow(curve_order - 1) + 1
    group = G1_to_pubkey(multiply(G1, secret))
    sealed = seal_share(device_pub, 0, 1, group, secret)
    check("a sealed share that was changed is refused",
          emu.send(IMPORT_SHARE, sealed[:160] + bytes([sealed[160] ^ 1]) + sealed[161:])[1] == BAD_IMPORT)
    emu.write(IMPORT_SHARE, sealed)
    emu.choose("Approve")
    check("a sealed share is taken once approved", emu.answer()[1] == 0x9000
          and emu.send(PUBKEY, struct.pack(">I", SLOT))[0] == group + b"\1")
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
    test_aggregates(emu)
    test_registration(emu)
    test_eip3076(emu)
    test_threshold(emu)
    test_keys(emu)
    emu.stop()
    test_restart()
    test_import()
    test_before_approval()
    test_daemon()
    test_combiner()
    print(f"\n{'FAILED: ' + ', '.join(FAILED) if FAILED else 'ALL PASSED'}")
    return bool(FAILED)


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        for left in Emulator.running:
            left.proc.kill()
