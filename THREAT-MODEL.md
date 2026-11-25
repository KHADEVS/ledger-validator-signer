# Threat model

A first version, for the prototype. It says what the design is meant to hold against, what it trusts, and where it does not hold yet.

## What is protected

1. **The validator key.** It never leaves the secure element in any form.
2. **The absence of a slashable signature.** For each key: no two blocks at one slot, no double vote, no surround vote.
3. **Where the rewards go.** The fee recipient in a builder registration.
4. **The validator's life.** A voluntary exit is not signed without a person.

Liveness is not protected, and neither is the choice of what to vote for. An attacker on the host can always stop the validator from signing, or have it vote for a head of their choosing. Neither can be slashed.

## The attacker

Has full control of the host: root, the daemon, the validator client, the USB link, the clock, and every file on disk. Can send any command to the device, in any order, as fast as the device answers, and can replay old ones. Can restart the host and the device, and cut the power at any moment.

Does not have the device in hand, and does not know its PIN.

## How each property is kept

| Property | Mechanism | Tested by |
| --- | --- | --- |
| The key stays inside | Derived in the secure element (EIP-2333) and kept in its memory while the app runs, or imported as a share. No command returns either. | no test can show an absence; see the command list |
| A share arrives intact and unseen | Sealed to a key made in the device (ECDH on P-256, HKDF-SHA256, AES-256-GCM), with the slot, the share's number, the validator's key and its starting point authenticated. The screen shows them and asks. | import tests: 16 ways to tamper, reject, what the screen shows |
| | The device shows a check of its import key, to compare with the one shown where the share is sealed. | import key test |
| A share's record can't go back | Its record starts where the import says. The same share again keeps the higher of the two; the same share in another slot is refused. | import tests |
| No slashable signature | The device parses the duty and computes the signing root. There is no command that signs a given root. | `a root given by the host is never signed` |
| | The record is checked and written to flash before the signature is made. | EIP-3076 interchange tests, 38 cases |
| | Two records alternate per key, with a counter and a checksum. A write cut short leaves the older one valid. | restart test (a power cut during the write is not tested) |
| | The record lives in the device's flash. The host has no command to lower or erase it in a release build. | `--release` test |
| | Every other duty is signed under a domain the device sets, different from the block and attestation domains. | API examples, per duty |
| | The network is fixed by a choice made on the device's screen. A duty for another network is refused. | enabling tests |
| Fee recipient | Set with a press, shown in full. A registration for another one is refused. The key in the registration is the device's own. | registration tests |
| Exit | Asked on the screen every time, with the validator index and the epoch. | exit tests |
| With 2-of-3 | Any two pairs of shares have one in common. Its record refuses the second, conflicting duty. Each share has its own record, and nothing is handed over between devices. | import tests, and three devices behind the combiner, with a takeover by another pair |

## What the design trusts

- **Ledger's operating system and the chip's firmware**, which are closed. They isolate the app, derive the key, do the BLS arithmetic and store the flash.
- **The person who presses the buttons**, to read the network, the fee recipient and the exit they approve.
- **The build.** An operator installs the app by hand, so they must check that the binary is the one the source gives. Builds are meant to be reproducible; this is not set up yet.
- **The recovery phrase.** A key derived from it can be restored on a second device, and two devices with the same key and separate records can sign a slashable pair. Threshold shares avoid this, as long as each share lives on one device.
- **The machine where a key is split.** The whole key is there once, in clear, and so are the shares before they are sealed. It should be offline and wiped afterwards. A key generation between the devices would remove it; it is not written.
- **The person who imports a share**, to compare the check of the import key, and to read the validator's key and the starting point on the screen. A starting point set too early lets the device sign again what the validator signed elsewhere.

## What does not hold yet

- **The fork version comes from the host.** A wrong one gives a signature that is valid on no real fork, so it cannot be used to slash. A version of another network with the same `genesis_validators_root` would be a problem; none exists to my knowledge.
- **The validator index of an exit is not checked against the key.** The device cannot know which index its key has. The person reads it on the screen.
- **Sync committee messages sign a root the host gives**, under the sync committee domain. That is the duty itself: the message is a block root. It is not slashable.
- **The device can't tell a share from any other number.** A share that does not belong to the key gives partial signatures that don't combine. The combiner finds it when the request carries its signing root; without it, the validator client is the one to reject the signature.
- **A slot can be given to another key.** The first key's record goes with it, and importing that key again later starts from what the new import says. It takes two presses on the device.
- **The combiner and the daemons speak plain HTTP.** They hold no secret and can't make a device sign a root of their choice, but anyone on that network can ask for signatures of valid duties. They belong on a private network.
- **A daemon or a combiner that lies** can do what a compromised host does with a single device, and no more: stop the signing, or have the devices vote for a head of its choice. It can't get a key, a slashable pair, an exit without a press or another fee recipient.
- **Replacing a device has no written procedure.** A share must live on one device: with the same share on two, two pairs no longer have a device in common. So the key is split again, each device that stays takes its new share and keeps its record, and the new device starts from the present epoch and slot. A share of the old split then combines with nothing, and the device that left is of no use to anyone. These parts are tested; the steps for an operator are not written. The whole key is needed for the new split.
- **The device runs unlocked.** A locked Ledger answers no command: the SDK refuses them before the app sees them. So the device's automatic PIN lock has to be off while it signs, as for Tezos bakers. Whoever reaches the device can then press its buttons: approve an exit or a setting the host asks for, or close the app. They can't read a key. The PIN protects a device that is switched off, not one that signs. Locking the device when the app is closed is not written.
- **Flash wear.** Every attestation writes one record. The number of writes the chip takes has not been measured.
- **A device that waits for a press signs nothing else**, so a host can stall a validator by asking for exits. This costs liveness only.
- **Power cut during a record write** is handled by design and not tested.
- **No audit.**
