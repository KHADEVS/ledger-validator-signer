//! Serves the Ethereum remote-signing API and passes each duty to the device.
//!
//! The daemon holds no key and decides nothing. It turns the JSON of a request into the fields
//! the device asks for; the device computes the signing root, keeps the slashing record and
//! signs or refuses. A daemon that lies gets a signature over what it sent, never over a root
//! of its choice.

mod device;

use device::Device;
use serde_json::{json, Value};
use std::io::Read;
use tiny_http::{Header, Method, Response, Server};

struct Config {
    device: String,
    listen: String,
    keys: u32,
    /// For builder registrations, whose requests carry no fork data.
    genesis: Option<([u8; 4], [u8; 32])>,
}

enum Failure {
    /// 400: the request is malformed, or asks for something this signer does not sign.
    Bad(String),
    /// 404: the key is not one of the device's.
    UnknownKey,
    /// 412: the device's slashing record refuses the duty.
    Slashable,
    /// 500: the device refused for another reason, or did not answer.
    Device(String),
}
use Failure::*;

type Res<T> = Result<T, Failure>;

fn bad<T>(why: impl Into<String>) -> Res<T> {
    Err(Bad(why.into()))
}

fn bytes(v: &Value, what: &str) -> Res<Vec<u8>> {
    let text = v.as_str().ok_or_else(|| Bad(format!("{what}: missing")))?;
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| Bad(format!("{what}: not hex")))?;
    hex::decode(digits).map_err(|_| Bad(format!("{what}: not hex")))
}

fn sized<const N: usize>(v: &Value, what: &str) -> Res<[u8; N]> {
    bytes(v, what)?
        .try_into()
        .map_err(|_| Bad(format!("{what}: {N} bytes expected")))
}

/// Integers are decimal strings in the API.
fn number(v: &Value, what: &str) -> Res<u64> {
    match v {
        Value::String(s) => s.parse().map_err(|_| Bad(format!("{what}: not a number"))),
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| Bad(format!("{what}: not a number"))),
        _ => bad(format!("{what}: missing")),
    }
}

fn le(v: &Value, what: &str) -> Res<[u8; 8]> {
    Ok(number(v, what)?.to_le_bytes())
}

/// key | fork version at `epoch` | genesis_validators_root
fn header(key: u32, request: &Value, epoch: u64) -> Res<Vec<u8>> {
    let info = &request["fork_info"];
    let fork = &info["fork"];
    let name = if epoch >= number(&fork["epoch"], "fork epoch")? {
        "current"
    } else {
        "previous"
    };
    // Both spellings appear in the specification's examples.
    let version = match &fork[format!("{name}_version")] {
        Value::Null => &fork[format!("{name}Version")],
        v => v,
    };
    let mut out = key.to_be_bytes().to_vec();
    out.extend(sized::<4>(version, "fork version")?);
    out.extend(sized::<32>(
        &info["genesis_validators_root"],
        "genesis_validators_root",
    )?);
    Ok(out)
}

/// slot | index | beacon_block_root | source | target, as the device reads it.
fn attestation_data(a: &Value) -> Res<Vec<u8>> {
    let mut out = le(&a["slot"], "slot")?.to_vec();
    out.extend(le(&a["index"], "index")?);
    out.extend(sized::<32>(&a["beacon_block_root"], "beacon_block_root")?);
    for side in ["source", "target"] {
        out.extend(le(&a[side]["epoch"], "epoch")?);
        out.extend(sized::<32>(&a[side]["root"], "root")?);
    }
    Ok(out)
}

fn ask(device: &mut Device, ins: u8, data: &[u8]) -> Res<Vec<u8>> {
    match device.send(ins, data) {
        Ok((answer, device::OK)) => Ok(answer),
        Ok((_, device::SLASHABLE)) => Err(Slashable),
        Ok((_, device::NOT_ENABLED)) => {
            Err(Device("this network is not enabled on the device".into()))
        }
        Ok((_, device::SETTING)) => {
            bad("the device has approved another fee recipient or gas limit")
        }
        Ok((_, device::DENIED)) => Err(Device("rejected on the device".into())),
        Ok((_, status)) => Err(Device(format!("the device answered {status:04X}"))),
        Err(e) => Err(Device(format!("no answer from the device: {e}"))),
    }
}

fn sign(
    device: &mut Device,
    config: &Config,
    key: u32,
    public_key: &[u8],
    r: &Value,
) -> Res<Vec<u8>> {
    let kind = r["type"].as_str().unwrap_or("");
    match kind {
        "ATTESTATION" => {
            let a = &r["attestation"];
            let mut duty = header(key, r, number(&a["target"]["epoch"], "target epoch")?)?;
            duty.extend(attestation_data(a)?);
            ask(device, device::ATTESTATION, &duty)
        }
        "BLOCK_V2" => {
            let h = &r["beacon_block"]["block_header"];
            if h.is_null() {
                return bad("only block headers are signed: send beacon_block.block_header");
            }
            let mut duty = header(key, r, number(&h["slot"], "slot")? / 32)?;
            duty.extend(le(&h["slot"], "slot")?);
            duty.extend(le(&h["proposer_index"], "proposer_index")?);
            for field in ["parent_root", "state_root", "body_root"] {
                duty.extend(sized::<32>(&h[field], field)?);
            }
            ask(device, device::BLOCK, &duty)
        }
        "AGGREGATION_SLOT" => {
            let slot = &r["aggregation_slot"]["slot"];
            let mut duty = header(key, r, number(slot, "slot")? / 32)?;
            duty.extend(le(slot, "slot")?);
            ask(device, device::AGGREGATION_SLOT, &duty)
        }
        "RANDAO_REVEAL" => {
            let epoch = &r["randao_reveal"]["epoch"];
            let mut duty = header(key, r, number(epoch, "epoch")?)?;
            duty.extend(le(epoch, "epoch")?);
            ask(device, device::RANDAO, &duty)
        }
        "SYNC_COMMITTEE_MESSAGE" => {
            let m = &r["sync_committee_message"];
            let mut duty = header(key, r, number(&m["slot"], "slot")? / 32)?;
            duty.extend(sized::<32>(&m["beacon_block_root"], "beacon_block_root")?);
            ask(device, device::SYNC_MESSAGE, &duty)
        }
        "SYNC_COMMITTEE_SELECTION_PROOF" => {
            let m = &r["sync_aggregator_selection_data"];
            let mut duty = header(key, r, number(&m["slot"], "slot")? / 32)?;
            duty.extend(le(&m["slot"], "slot")?);
            duty.extend(le(&m["subcommittee_index"], "subcommittee_index")?);
            ask(device, device::SYNC_SELECTION, &duty)
        }
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" => {
            let m = &r["contribution_and_proof"];
            let c = &m["contribution"];
            let mut bits = bytes(&c["aggregation_bits"], "aggregation_bits")?;
            if bits.len() > 16 {
                return bad("aggregation_bits: at most 16 bytes");
            }
            bits.resize(16, 0);
            let mut start = header(key, r, number(&c["slot"], "slot")? / 32)?;
            start.push(2);
            start.extend(le(&m["aggregator_index"], "aggregator_index")?);
            start.extend(le(&c["slot"], "slot")?);
            start.extend(sized::<32>(&c["beacon_block_root"], "beacon_block_root")?);
            start.extend(le(&c["subcommittee_index"], "subcommittee_index")?);
            start.extend(bits);
            ask(device, device::BEGIN, &start)?;
            let mut end = sized::<96>(&c["signature"], "signature")?.to_vec();
            end.extend(sized::<96>(&m["selection_proof"], "selection_proof")?);
            ask(device, device::END, &end)
        }
        "AGGREGATE_AND_PROOF" | "AGGREGATE_AND_PROOF_V2" => {
            let outer = &r["aggregate_and_proof"];
            // The layout of an attestation changed in Electra, and its hashing in Gloas.
            let kind = match outer["version"].as_str() {
                Some("GLOAS") => 3u8,
                Some("ELECTRA" | "FULU") => 1,
                _ => 0,
            };
            let m = if outer["data"].is_null() {
                outer
            } else {
                &outer["data"]
            };
            let aggregate = &m["aggregate"];
            let bits = bytes(&aggregate["aggregation_bits"], "aggregation_bits")?;
            let mut start = header(key, r, number(&aggregate["data"]["slot"], "slot")? / 32)?;
            start.push(kind);
            start.extend(le(&m["aggregator_index"], "aggregator_index")?);
            start.extend(attestation_data(&aggregate["data"])?);
            start.extend((bits.len() as u32).to_be_bytes());
            if kind != 0 {
                start.extend(sized::<8>(&aggregate["committee_bits"], "committee_bits")?);
            } else {
                start.extend([0u8; 8]);
            }
            ask(device, device::BEGIN, &start)?;
            for part in bits.chunks(255) {
                ask(device, device::BITS, part)?;
            }
            let mut end = sized::<96>(&aggregate["signature"], "signature")?.to_vec();
            end.extend(sized::<96>(&m["selection_proof"], "selection_proof")?);
            ask(device, device::END, &end)
        }
        // The device shows the validator and the epoch, and waits for a press.
        "VOLUNTARY_EXIT" => {
            let m = &r["voluntary_exit"];
            let mut duty = header(key, r, number(&m["epoch"], "epoch")?)?;
            duty.extend(le(&m["epoch"], "epoch")?);
            duty.extend(le(&m["validator_index"], "validator_index")?);
            ask(device, device::EXIT, &duty)
        }
        "VALIDATOR_REGISTRATION" => {
            let Some((version, root)) = config.genesis else {
                return bad(
                    "registrations need --genesis-fork-version and --genesis-validators-root",
                );
            };
            let m = &r["validator_registration"];
            if bytes(&m["pubkey"], "pubkey")? != public_key {
                return bad("pubkey: not the key that is asked to sign");
            }
            let mut duty = key.to_be_bytes().to_vec();
            duty.extend(version);
            duty.extend(root);
            duty.extend(sized::<20>(&m["fee_recipient"], "fee_recipient")?);
            duty.extend(le(&m["gas_limit"], "gas_limit")?);
            duty.extend(le(&m["timestamp"], "timestamp")?);
            ask(device, device::REGISTRATION, &duty)
        }
        other => bad(format!("{other}: not signed by this device")),
    }
}

fn text(status: u16, body: impl Into<String>) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body).with_status_code(status)
}

fn serve(config: &Config) -> Result<(), String> {
    let mut device =
        Device::connect(&config.device).map_err(|e| format!("device at {}: {e}", config.device))?;
    let mut keys = Vec::new();
    for index in 0..config.keys {
        match device.send(device::PUBLIC_KEY, &index.to_be_bytes()) {
            Ok((key, device::OK)) => keys.push(key),
            Ok((_, status)) => {
                return Err(format!(
                    "public key {index}: the device answered {status:04X}"
                ))
            }
            Err(e) => return Err(format!("public key {index}: {e}")),
        }
    }
    let server =
        Server::http(&config.listen).map_err(|e| format!("listening on {}: {e}", config.listen))?;
    eprintln!("{} keys, listening on {}", keys.len(), config.listen);
    let json_type = Header::from_bytes("Content-Type", "application/json").expect("a valid header");

    for mut request in server.incoming_requests() {
        let url = request.url().to_owned();
        let response = if request.method() == &Method::Get && url == "/upcheck" {
            text(200, "OK")
        } else if request.method() == &Method::Get && url == "/api/v1/eth2/publicKeys" {
            let list: Vec<String> = keys
                .iter()
                .map(|k| format!("0x{}", hex::encode(k)))
                .collect();
            text(200, json!(list).to_string()).with_header(json_type.clone())
        } else if let (Method::Post, Some(id)) =
            (request.method(), url.strip_prefix("/api/v1/eth2/sign/"))
        {
            let wants_json = request
                .headers()
                .iter()
                .any(|h| h.field.equiv("Accept") && h.value.as_str().contains("json"));
            let mut body = String::new();
            let outcome = request
                .as_reader()
                .take(1 << 20)
                .read_to_string(&mut body)
                .map_err(|_| Bad("unreadable body".into()))
                .and_then(|_| {
                    serde_json::from_str::<Value>(&body).map_err(|e| Bad(format!("not JSON: {e}")))
                })
                .and_then(|parsed| {
                    let wanted =
                        hex::decode(id.trim_start_matches("0x")).map_err(|_| UnknownKey)?;
                    let key = keys.iter().position(|k| *k == wanted).ok_or(UnknownKey)?;
                    sign(&mut device, config, key as u32, &wanted, &parsed)
                });
            match outcome {
                Ok(signature) if wants_json => {
                    let body = json!({ "signature": format!("0x{}", hex::encode(signature)) });
                    text(200, body.to_string()).with_header(json_type.clone())
                }
                Ok(signature) => text(200, format!("0x{}", hex::encode(signature))),
                Err(Bad(why)) => text(400, why),
                Err(UnknownKey) => text(404, "unknown public key"),
                Err(Slashable) => text(412, "refused by the device's slashing record"),
                Err(Device(why)) => text(500, why),
            }
        } else {
            text(404, "not found")
        };
        let _ = request.respond(response);
    }
    Ok(())
}

fn arguments() -> Result<Config, String> {
    let mut config = Config {
        device: "127.0.0.1:9999".into(),
        listen: "127.0.0.1:9000".into(),
        keys: 1,
        genesis: None,
    };
    let (mut version, mut root) = (None, None);
    let mut args = std::env::args().skip(1);
    while let Some(name) = args.next() {
        let value = args.next().ok_or(format!("{name}: a value is expected"))?;
        let fixed = |n: usize| {
            hex::decode(value.trim_start_matches("0x"))
                .ok()
                .filter(|b| b.len() == n)
                .ok_or(format!("{name}: {n} bytes in hex expected"))
        };
        match name.as_str() {
            "--device" => config.device = value,
            "--listen" => config.listen = value,
            "--keys" => config.keys = value.parse().map_err(|_| "--keys: a number is expected")?,
            "--genesis-fork-version" => {
                version = Some(<[u8; 4]>::try_from(fixed(4)?).expect("4 bytes"))
            }
            "--genesis-validators-root" => {
                root = Some(<[u8; 32]>::try_from(fixed(32)?).expect("32 bytes"))
            }
            _ => return Err(format!("{name}: unknown option")),
        }
    }
    config.genesis = version.zip(root);
    Ok(config)
}

fn main() {
    if let Err(why) = arguments().and_then(|config| serve(&config)) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}
