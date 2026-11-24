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
- **Threshold:** the same code signs with a 2-of-3 share. Any two quorums share a device, and that device refuses the conflicting vote.

Keys are derived on the device at `m/12381/3600/i/0/0` ([EIP-2334](https://eips.ethereum.org/EIPS/eip-2334)). The app can't derive anything else.

What the design trusts, and where it does not hold yet, is in [THREAT-MODEL.md](THREAT-MODEL.md).

## Duties

Every request type of the [remote-signing API](https://github.com/ethereum/remote-signing-api) that has a published signing root, except deposits:

| Duty | On the device |
| --- | --- |
| Attestation | slashing record, then signs |
| Block (header, Bellatrix and later) | slashing record, then signs |
| Aggregation slot, RANDAO reveal | signs |
| Aggregate and proof, before and since Electra | the bit list arrives in parts and is hashed as it comes, so its size needs no memory |
| Sync committee message, selection proof, contribution and proof | signs |
| Voluntary exit | asks on the screen |
| Builder registration | only for the approved fee recipient and gas limit |

Not signed: deposits (signed once, when a key is created), full blocks from before Bellatrix, and the Gloas payload duties, whose examples have no published root yet.

## The daemon

`daemon/` is a small Rust program: `GET /upcheck`, `GET /api/v1/eth2/publicKeys` and `POST /api/v1/eth2/sign/{key}`. It holds no key and decides nothing. It turns the JSON of a request into the fields the device asks for. A slashable duty comes back as `412`, as the API says.

Today it talks to the emulator over TCP. A USB transport is still to write.

## What is tested

`tests/run.py` drives a test build in [Speculos](https://github.com/LedgerHQ/speculos):

| Test | Source |
| --- | --- |
| 22 examples, one per duty and fork: the signature verifies against the published signing root | [remote-signing-api](https://github.com/ethereum/remote-signing-api) |
| The same examples as HTTP requests to the daemon, the device behind it | same |
| Every accept and refuse of the 38 cases matches | [slashing-protection-interchange-tests](https://github.com/eth-clients/slashing-protection-interchange-tests) |
| Aggregates with 22 sizes of bit list, from empty to the 131,072 bits of the limit, against a root computed apart from the device | this repository |
| Exit: reject and approve, what the screen shows. Registration: another fee recipient, gas limit or network is refused | this repository |
| 2-of-3 threshold: the three pairs sign for the group key, one share does not | this repository |
| The record survives a restart; double and surround votes are still refused | this repository |
| The screen names the network, and the host can't swap it during the approval | this repository |
| Nothing is signed before a network is enabled | this repository |

`tests/faults.py` breaks the app on purpose, one fault at a time (17 of them), and checks that the suite notices each one.

Signatures are verified with [py_ecc](https://github.com/ethereum/py_ecc), apart from the emulator's own BLS code.

One example upstream does not match its content: `AGGREGATE_AND_PROOF_V2 (GLOAS)` has the same aggregate as the Fulu example and another signing root. The tests use the Fulu root for it.

## What is missing

- **A physical device.** The emulator runs BLS on the host, so the time per signature on the chip is unknown, and so is the flash wear.
- **Real validator clients.** The daemon passes the API's examples; no client has been run against it.
- The Gloas payload duties.
- EIP-3076 import with a confirmation on the device, and export. Today's import exists only in test builds.
- Creating the shares: a DKG between devices. Test builds receive a share from the host, which a real one must never do. Only attestations are signed with a share so far.
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
| `06` | public key | key index, 4 bytes big endian |
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

Errors: `B101` slashable, `B102` network not enabled, `B103` unknown key, `B104` busy, `B105` a duty in parts that does not hold together, `B106` not the approved fee recipient or gas limit.

## Licence

[Apache-2.0](LICENSE). Built on Ledger's [app-btec](https://github.com/LedgerHQ/app-btec), see [NOTICE](NOTICE).
