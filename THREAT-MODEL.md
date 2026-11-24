# Threat model

A first version, for the prototype. It says what the design is meant to hold against, what it trusts, and where it does not hold yet.

## What is protected

1. **The validator key.** It never leaves the secure element in any form.
2. **The absence of a slashable signature.** For each key: no two blocks at one slot, no double vote, no surround vote.
3. **Where the rewards go.** The fee recipient in a builder registration.
4. **The validator's life.** A voluntary exit is not signed without a person.

Liveness is not protected. An attacker on the host can always stop the validator from signing.

## The attacker

Has full control of the host: root, the daemon, the validator client, the USB link, the clock, and every file on disk. Can send any command to the device, in any order, as fast as the device answers, and can replay old ones. Can restart the host and the device, and cut the power at any moment.

Does not have the device in hand, and does not know its PIN.

## How each property is kept

| Property | Mechanism | Tested by |
| --- | --- | --- |
| The key stays inside | Derived in the secure element (EIP-2333). No command returns it. | no test can show an absence; see the command list |
| No slashable signature | The device parses the duty and computes the signing root. There is no command that signs a given root. | `a root given by the host is never signed` |
| | The record is checked and written to flash before the signature is made. | EIP-3076 interchange tests, 38 cases |
| | Two records alternate per key, with a counter and a checksum. A write cut short leaves the older one valid. | restart test (a power cut during the write is not tested) |
| | The record lives in the device's flash. The host has no command to lower or erase it in a release build. | `--release` test |
| | Every other duty is signed under a domain the device sets, different from the block and attestation domains. | API examples, per duty |
| | The network is fixed by a choice made on the device's screen. A duty for another network is refused. | enabling tests |
| Fee recipient | Set with a press, shown in full. A registration for another one is refused. The key in the registration is the device's own. | registration tests |
| Exit | Asked on the screen every time, with the validator index and the epoch. | exit tests |
| With 2-of-3 | Any two quorums share a device. That device's record refuses the second, conflicting duty. | threshold test (the record of a share is the same code) |

## What the design trusts

- **Ledger's operating system and the chip's firmware**, which are closed. They isolate the app, derive the key, do the BLS arithmetic and store the flash.
- **The person who presses the buttons**, to read the network, the fee recipient and the exit they approve.
- **The build.** An operator installs the app by hand, so they must check that the binary is the one the source gives. Builds are meant to be reproducible; this is not set up yet.
- **The recovery phrase.** A key derived from it can be restored on a second device, and two devices with the same key and separate records can sign a slashable pair. Threshold shares avoid this, as long as each share lives on one device.

## What does not hold yet

- **The fork version comes from the host.** A wrong one gives a signature that is valid on no real fork, so it cannot be used to slash. A version of another network with the same `genesis_validators_root` would be a problem; none exists to my knowledge.
- **The validator index of an exit is not checked against the key.** The device cannot know which index its key has. The person reads it on the screen.
- **Sync committee messages sign a root the host gives**, under the sync committee domain. That is the duty itself: the message is a block root. It is not slashable.
- **Shares come from the host in test builds.** A real threshold setup needs a key generation between devices, which is not written.
- **Flash wear.** Every attestation writes one record. The number of writes the chip takes has not been measured.
- **A device that waits for a press signs nothing else**, so a host can stall a validator by asking for exits. This costs liveness only.
- **Power cut during a record write** is handled by design and not tested.
- **No audit.**
