# ledger-validator-signer

An Ethereum validator signer that runs inside the secure element of a Ledger Nano S Plus, with a small daemon that serves the standard remote-signing API in front of it.

**Prototype. It has only run in Ledger's emulator, it is not audited, and it must not be used with a real key.**

The goal: getting root on the host gives an attacker neither the validator key nor a slashable signature.

## What it does

- **It computes the signing root itself**, from the fields of the duty. There is no command that signs a root given by the host.
- **It keeps the slashing record inside** ([EIP-3076](https://eips.ethereum.org/EIPS/eip-3076), minimal strategy). The record is written to the device's flash before the signature is made. Two records alternate per key, so a write cut by a power loss leaves the previous one, and nothing was signed. The host cannot roll it back.
- **It picks the domain of every duty.** An aggregate, a sync committee message or a RANDAO reveal can't come out as a block or a vote.
- **Automatic signing has to be enabled on the device**, for one network that the screen names. A network it doesn't know is shown as its full `genesis_validators_root`.
- **An exit needs a press every time.** The screen shows the validator index and the epoch.
- **A builder registration is signed only for the fee recipient and gas limit approved on the device**, and the public key in it is the device's own, not one sent by the host.
- **A key can be held as shares, one per device.** A share is imported encrypted to a key made inside the device, which shows what it imports and asks. Two devices of three then sign for the key, and a small combiner gives the validator client the key's signature. Any two pairs of devices have one in common, and that one refuses the conflicting vote.

Keys are derived on the device at `m/12381/3600/i/0/0` ([EIP-2334](https://eips.ethereum.org/EIPS/eip-2334)). The app can't derive anything else. A key is derived once and stays in the secure element's memory while the app runs: on the chip the derivation takes about a second per level of the path ([measured](#what-is-missing)), too long to redo for every signature.

## Key shares

An operator who already has a validator key splits it in three on a machine they trust, and loads one share into each device:

1. The device makes a P-256 key at first use and gives its public half. Its screen shows a check of it, to compare with the one shown where the share is encrypted, so that a host in between can't put its own key in its place.
2. The share is sealed to that key (ECDH, HKDF-SHA256, AES-256-GCM). The slot, the share's number, the validator's public key and what the validator signed before are sent in clear, and authenticated with the share.
3. The screen shows the slot, the share's number, both ends of the validator's key and the point from which the device will sign. Nothing is stored without a press.

The record of the slot starts at that point, as in an EIP-3076 import: an existing validator can't be made to sign again what it signed elsewhere. Importing the same share again never lowers its record. A slot signs every duty a derived key signs.

What the design trusts, and where it does not hold yet, is in [THREAT-MODEL.md](THREAT-MODEL.md).

## Duties

Every request type of the [remote-signing API](https://github.com/ethereum/remote-signing-api) that has a published signing root, except deposits:

| Duty | On the device |
| --- | --- |
| Attestation | slashing record, then signs |
| Block (header, Bellatrix and later) | slashing record, then signs |
| Aggregation slot, RANDAO reveal | signs |
| Aggregate and proof, in its three forms (before Electra, since Electra, since Gloas) | the bit list arrives in parts and is hashed as it comes, so its size needs no memory |
| Sync committee message, selection proof, contribution and proof | signs |
| Voluntary exit | asks on the screen |
| Builder registration | only for the approved fee recipient and gas limit |

Not signed: deposits (signed once, when a key is created), full blocks from before Bellatrix, and the Gloas payload duties, whose examples have no published root yet.

## The daemon

`daemon/` is a small Rust program: `GET /upcheck`, `GET /api/v1/eth2/publicKeys` and `POST /api/v1/eth2/sign/{key}`. It holds no key and decides nothing. It turns the JSON of a request into the fields the device asks for. A slashable duty comes back as `412`, as the API says.

For a key held as shares, each device's daemon gives a partial signature at `POST /partial/v1/eth2/sign/{key}` and lists its shares at `GET /api/v1/shares`. It does not offer such a key in `publicKeys`: a partial signature is of no use to a validator client. A daemon started with `--combine http://a:9000,http://b:9000,http://c:9000` holds no device. It serves the standard API, asks every signer at once, and answers with the key's signature once two of them have signed. When the request carries its signing root, a partial signature that is wrong is found and left out.

Today a daemon talks to the emulator over TCP, and to the other daemons over plain HTTP. A USB transport is still to write.

## What is tested

`tests/run.py` drives a test build in [Speculos](https://github.com/LedgerHQ/speculos):

| Test | Source |
| --- | --- |
| 22 examples, one per duty and fork: the signature verifies against the published signing root | [remote-signing-api](https://github.com/ethereum/remote-signing-api) |
| The same examples as HTTP requests to the daemon, the device behind it | same |
| Every accept and refuse of the 38 cases matches | [slashing-protection-interchange-tests](https://github.com/eth-clients/slashing-protection-interchange-tests) |
| Aggregates with 38 sizes of bit list, from empty to the 131,072 bits of the limit, in the three forms, against a root computed apart from the device | this repository |
| Exit: reject and approve, what the screen shows. Registration: another fee recipient, gas limit or network is refused | this repository |
| 2-of-3 threshold: the three pairs sign for the group key, one share does not | this repository |
| Import of a share: 16 ways to tamper with it are refused, the screen shows what is imported, the record starts where the import says and never goes back, three slots sign a vote, a block and a RANDAO reveal as 2 of 3 | this repository |
| Three devices with one share each, a daemon in front of each and a combiner: the API's examples are signed for the key, an exit needs a press on the devices, a wrong share is left out, one device down changes nothing, two down and nothing is signed | [remote-signing-api](https://github.com/ethereum/remote-signing-api) |
| Keys used in turn each sign with their own key | this repository |
| The record and the shares survive a restart; double and surround votes are still refused | this repository |
| The screen names the network, and the host can't swap it during the approval | this repository |
| Nothing is signed before a network is enabled | this repository |

`tests/faults.py` breaks the app on purpose, one fault at a time (26 of them), and checks that the suite notices each one.

Signatures are verified with [py_ecc](https://github.com/ethereum/py_ecc), apart from the emulator's own BLS code.

Gloas hashes an attestation another way ([EIP-7688](https://eips.ethereum.org/EIPS/eip-7688): progressive lists and containers). The Gloas aggregate example has the same content as the Fulu one and another root, and both are matched.

## What is missing

- **A physical device.** The emulator runs BLS on the host, and the app has not run on the chip. What is measured so far is the key derivation, through Ledger's Ethereum app, which computes a BLS public key for a path under `m/12381/3600` without a confirmation. On a Ledger Flex, which has [the same secure element](https://developers.ledger.com/docs/device-app/explanation/ledger-os/hardware-architecture) as the Nano S Plus, at five path depths and five runs each: 1.09 s for one level of EIP-2333 derivation, so 5.4 s for a validator key, and 0.27 s for the rest of the command, one multiplication in G1 included. The signature itself, a hash to G2 and a multiplication in G2, is not timed yet, and neither is the flash wear. Tezos's developers [found](https://research-development.nomadic-labs.com/seoul-is-live.html) BLS signing on Ledger devices too slow for their chain, where a key signs twice per block; their app derived the key [twice for every signature](https://github.com/trilitech/ledger-app-tezos-baking/blob/17bb4f87b12eb09193026991fa790c9662c23345/src/crypto.c#L157-L159). An Ethereum validator's regular duties are two signatures per epoch. Timing the signature on a Nano S Plus comes before anything else.
- **Real validator clients.** The daemon passes the API's examples; no client has been run against it.
- The Gloas payload duties.
- EIP-3076 import and export for the keys derived on the device. A share brings its starting point with it; a derived key is new and has none.
- Creating the shares between the devices (a DKG), so that the key never exists whole. Today it is split on a machine the operator trusts.
- The device can't check that a share belongs to the key it is imported for. A wrong one gives partial signatures that don't combine.
- One fee recipient for all keys, where an operator may want one per key. A way to disable automatic signing, and flash wear levelling.
- While the device waits for a press, it signs nothing else.

An operator would install the app by hand. It is not in Ledger's catalogue, which requires an audit by one of Ledger's partners.

## Build and test

With [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder):

```sh
make BOLOS_SDK=$NANOSP_SDK TEST_BUILD=1
sh tests/fetch.sh
pip install -r tests/requirements.txt
cargo build --release --manifest-path daemon/Cargo.toml
DAEMON=daemon/target/release/validator-signer-daemon python3 tests/run.py
```

Without `TEST_BUILD=1` the test commands don't exist.

## Commands

`CLA` is `E0`, `P1` and `P2` are 0. Integers inside a duty are little endian, as in SSZ. A duty starts with a header: key index 4 (big endian), fork version 4, `genesis_validators_root` 32.

| INS | Command | Data |
| --- | --- | --- |
| `03` | version | |
| `04` | app name | |
| `06` | public key; for a slot (32 to 35), the validator's key and the share's number | key index, 4 bytes big endian |
| `20` | enable automatic signing (asked on the device) | genesis_validators_root 32 |
| `21` | attestation | header, AttestationData 128 |
| `22` | block | header, BeaconBlockHeader 112 |
| `23` | read a key's record | key 4 |
| `27` | aggregation slot | header, slot 8 |
| `28` | RANDAO reveal | header, epoch 8 |
| `29` | sync committee message | header, beacon_block_root 32 |
| `2A` | sync committee selection proof | header, slot 8, subcommittee_index 8 |
| `2C` | start of an aggregate or a contribution | header, kind 1, aggregator_index 8, then the fixed fields |
| `2D` | bytes of `aggregation_bits`, in order | up to 255 |
| `2E` | end: signs | aggregate signature 96, selection_proof 96 |
| `30` | voluntary exit (asked on the device) | header, epoch 8, validator_index 8 |
| `31` | set the fee recipient and gas limit (asked on the device) | fee recipient 20, gas limit 8 |
| `32` | builder registration | header with the genesis fork version, fee recipient 20, gas limit 8, timestamp 8 |
| `33` | the key to encrypt a share to (its check is shown on the device) | |
| `34` | import a share (asked on the device) | slot 1, share number 1, validator key 48, source 8, target 8, block slot 8, flags 1 (1: has voted, 2: has proposed), sender key 65, nonce 12, sealed share 32, tag 16 |

A key index from 32 to 35 names the slot of an imported share, and is used like any other key.

Errors: `B101` slashable, `B102` network not enabled, `B103` unknown key or empty slot, `B104` busy, `B105` a duty in parts that does not hold together, `B106` not the approved fee recipient or gas limit, `B107` a share that does not decrypt or that the device can't hold.

## Licence

[Apache-2.0](LICENSE). Built on Ledger's [app-btec](https://github.com/LedgerHQ/app-btec), see [NOTICE](NOTICE).
