# ledger-validator-signer

An Ethereum validator signer that runs inside the secure element of a Ledger Nano S Plus.

**Prototype. It has only run in Ledger's emulator, it is not audited, and it must not be used with a real key.**

The goal: getting root on the host gives an attacker neither the validator key nor a slashable signature.

## What it does

- **It computes the signing root itself**, from the fields of the duty. There is no command that signs a root given by the host.
- **It keeps the slashing record inside** ([EIP-3076](https://eips.ethereum.org/EIPS/eip-3076), minimal strategy). The record is written to the device's flash before the signature is made. Two records alternate per key, so a write cut by a power loss leaves the previous one, and nothing was signed. The host cannot roll it back.
- **Automatic signing has to be enabled on the device**, for one network that the screen names. A network it doesn't know is shown as its full `genesis_validators_root`.
- **Threshold:** the same code signs with a 2-of-3 share. Any two quorums share a device, and that device refuses the conflicting vote.

Keys are derived on the device at `m/12381/3600/i/0/0` ([EIP-2334](https://eips.ethereum.org/EIPS/eip-2334)). The app can't derive anything else.

## What is tested

`tests/run.py` drives a test build in [Speculos](https://github.com/LedgerHQ/speculos):

| Test | Source |
| --- | --- |
| Attestation and block header (Bellatrix to Gloas) signatures verify against the published signing root | [remote-signing-api](https://github.com/ethereum/remote-signing-api) examples |
| Every accept and refuse of the 38 cases matches | [slashing-protection-interchange-tests](https://github.com/eth-clients/slashing-protection-interchange-tests) |
| 2-of-3 threshold: the three pairs sign for the group key, one share does not | this repository |
| The record survives a restart; double and surround votes are still refused | this repository |
| The screen names the network, and the host can't swap it during the approval | this repository |

`tests/faults.py` breaks the app on purpose, one fault at a time, and checks that the suite notices each one.

Signatures are verified with [py_ecc](https://github.com/ethereum/py_ecc), apart from the emulator's own BLS code.

## What is missing

- **A physical device.** The emulator runs BLS on the host, so the time per signature on the chip is unknown, and so is the flash wear.
- Every duty other than attestations and blocks: aggregates, RANDAO, sync committee, registrations, exits, and the Gloas payload duties.
- The daemon that exposes the remote-signing API, and tests with real validator clients.
- EIP-3076 import with a confirmation on the device, and export. Today's import exists only in test builds.
- Creating the shares: a DKG between devices. Test builds receive a share from the host, which a real one must never do.
- A way to disable automatic signing, and flash wear levelling.

An operator would install the app by hand. It is not in Ledger's catalogue, which requires an audit by one of Ledger's partners.

## Build and test

With [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder):

```sh
make BOLOS_SDK=$NANOSP_SDK TEST_BUILD=1
sh tests/fetch.sh
pip install -r tests/requirements.txt
python3 tests/run.py
```

Without `TEST_BUILD=1` the test commands don't exist.

## Commands

`CLA` is `E0`, `P1` and `P2` are 0. Integers inside a duty are little endian, as in SSZ.

| INS | Command | Data |
| --- | --- | --- |
| `03` | version | |
| `04` | app name | |
| `06` | public key | key index, 4 bytes big endian |
| `20` | enable automatic signing (on-device approval) | genesis_validators_root, 32 |
| `21` | sign an attestation | key 4, fork version 4, genesis root 32, AttestationData 128 |
| `22` | sign a block | key 4, fork version 4, genesis root 32, BeaconBlockHeader 112 |
| `23` | read a key's record | key 4 |

Errors: `B101` slashable, `B102` network not enabled, `B103` unknown key, `B104` busy.

## Licence

[Apache-2.0](LICENSE). Built on Ledger's [app-btec](https://github.com/LedgerHQ/app-btec), see [NOTICE](NOTICE).
