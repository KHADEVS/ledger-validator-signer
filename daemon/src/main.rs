//! Serves the Ethereum remote-signing API and passes each duty to the device.
//!
//! The daemon holds no key and decides nothing. It turns the JSON of a request into the fields
//! the device asks for; the device computes the signing root, keeps the slashing record and
//! signs or refuses. A daemon that lies gets a signature over what it sent, never over a root
//! of its choice.
//!
//! A key can also be held as shares, one per device. Each device's daemon then gives a partial
//! signature, and a daemon started with `--combine` asks them all and answers the validator
//! client with the key's signature once enough of them have signed.

mod combine;
mod device;

use device::Device;
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

/// The device numbers the slots of imported shares after its own keys.
const FIRST_SLOT: u32 = 32;
const SLOTS: u32 = 4;
/// An exit waits for a press on each device.
const WAIT: Duration = Duration::from_secs(150);

struct Config {
    device: String,
    listen: String,
    keys: u32,
    /// For builder registrations, whose requests carry no fork data.
    genesis: Option<([u8; 4], [u8; 32])>,
    /// Addresses of the daemons that each hold a share. With them, this one holds no device.
    combine: Vec<String>,
    threshold: usize,
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

fn json_type() -> Header {
    Header::from_bytes("Content-Type", "application/json").expect("a valid header")
}

/// Reads a signing request for the key `id` and answers with what `signer` gives: it gets the
/// request, the key and the request's text.
fn answer(
    request: &mut Request,
    id: &str,
    signer: impl FnOnce(&Value, &[u8], &str) -> Res<Vec<u8>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
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
            let wanted = hex::decode(id.trim_start_matches("0x")).map_err(|_| UnknownKey)?;
            signer(&parsed, &wanted, &body)
        });
    match outcome {
        Ok(signature) if wants_json => {
            let body = json!({ "signature": format!("0x{}", hex::encode(signature)) });
            text(200, body.to_string()).with_header(json_type())
        }
        Ok(signature) => text(200, format!("0x{}", hex::encode(signature))),
        Err(Bad(why)) => text(400, why),
        Err(UnknownKey) => text(404, "unknown public key"),
        Err(Slashable) => text(412, "refused by the device's slashing record"),
        Err(Device(why)) => text(500, why),
    }
}

/// Which signer holds which share: the key, the signer's address, the share's number.
type Holder = (Vec<u8>, String, u8);

fn holders(config: &Config) -> Vec<Holder> {
    let mut out = Vec::new();
    for address in &config.combine {
        let url = format!("{address}/api/v1/shares");
        let Ok((200, body)) = combine::http("GET", &url, "", Duration::from_secs(10)) else {
            continue;
        };
        let Ok(Value::Array(list)) = serde_json::from_str::<Value>(&body) else {
            continue;
        };
        for entry in list {
            if let (Ok(key), Some(share)) =
                (bytes(&entry["pubkey"], "pubkey"), entry["share"].as_u64())
            {
                out.push((key, address.clone(), share as u8));
            }
        }
    }
    out
}

/// Asks every signer that holds a share of the key, and combines enough partial signatures.
fn combined(
    config: &Config,
    known: &[Holder],
    parsed: &Value,
    wanted: &[u8],
    body: &str,
) -> Res<Vec<u8>> {
    let key: [u8; 48] = wanted.try_into().map_err(|_| UnknownKey)?;
    let asked: Vec<&Holder> = known.iter().filter(|(k, _, _)| k == wanted).collect();
    if asked.is_empty() {
        return Err(UnknownKey);
    }
    let id = format!("0x{}", hex::encode(wanted));
    // All at once: each device signs or refuses on its own record, whatever the others do.
    let answers: Vec<std::io::Result<(u16, String)>> = std::thread::scope(|scope| {
        let waiting: Vec<_> = asked
            .iter()
            .map(|(_, address, share)| {
                let url = format!("{address}/partial/v1/eth2/sign/{id}?share={share}");
                scope.spawn(move || combine::http("POST", &url, body, WAIT))
            })
            .collect();
        waiting
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("the request stopped")))
            })
            .collect()
    });
    let mut parts: Vec<(u8, [u8; 96])> = Vec::new();
    let (mut refused, mut rejected, mut other) = (0, None, Vec::new());
    for ((_, address, share), answer) in asked.iter().zip(answers) {
        match answer {
            Ok((200, text)) => {
                let signature = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| sized::<96>(&v["signature"], "signature").ok());
                match signature {
                    Some(signature) => parts.push((*share, signature)),
                    None => other.push(format!("{address}: not a signature")),
                }
            }
            Ok((412, _)) => refused += 1,
            Ok((400, text)) => rejected = Some(text),
            Ok((status, text)) => other.push(format!("{address}: {status} {text}")),
            Err(e) => other.push(format!("{address}: {e}")),
        }
    }
    if parts.len() < config.threshold {
        if refused > 0 {
            return Err(Slashable);
        }
        if let Some(why) = rejected {
            return bad(why);
        }
        return Err(Device(format!(
            "{} partial signatures of the {} needed ({})",
            parts.len(),
            config.threshold,
            other.join("; ")
        )));
    }
    // A request may give its signing root. Nothing is signed from it here: it only tells which
    // partial signatures to leave out when one of them is wrong.
    let root = sized::<32>(&parsed["signingRoot"], "signingRoot")
        .or_else(|_| sized::<32>(&parsed["signing_root"], "signing_root"))
        .ok();
    for chosen in combine::subsets(parts.len(), config.threshold) {
        let chosen: Vec<(u8, [u8; 96])> = chosen.iter().map(|at| parts[*at]).collect();
        let Some(signature) = combine::combine(&chosen) else {
            continue;
        };
        let right = match &root {
            Some(root) => combine::verify(&key, root, &signature),
            None => true,
        };
        if right {
            return Ok(signature.to_vec());
        }
    }
    Err(Device(
        "the partial signatures do not give the key's signature".into(),
    ))
}

/// No device here: the validator client talks to this daemon, which asks the signers.
fn serve_combined(config: &Config) -> Result<(), String> {
    let server =
        Server::http(&config.listen).map_err(|e| format!("listening on {}: {e}", config.listen))?;
    let mut known = holders(config);
    eprintln!(
        "{} signers, {} shares seen, {} needed, listening on {}",
        config.combine.len(),
        known.len(),
        config.threshold,
        config.listen
    );
    for mut request in server.incoming_requests() {
        let url = request.url().to_owned();
        let response = if request.method() == &Method::Get && url == "/upcheck" {
            text(200, "OK")
        } else if request.method() == &Method::Get && url == "/api/v1/eth2/publicKeys" {
            known = holders(config);
            // A key is offered once enough signers hold a share of it.
            let mut keys: Vec<&Vec<u8>> = known.iter().map(|(key, _, _)| key).collect();
            keys.sort();
            keys.dedup();
            let list: Vec<String> = keys
                .into_iter()
                .filter(|key| {
                    known.iter().filter(|(k, _, _)| k == *key).count() >= config.threshold
                })
                .map(|key| format!("0x{}", hex::encode(key)))
                .collect();
            text(200, json!(list).to_string()).with_header(json_type())
        } else if let (Method::Post, Some(id)) =
            (request.method(), url.strip_prefix("/api/v1/eth2/sign/"))
        {
            let id = id.to_owned();
            answer(&mut request, &id, |parsed, wanted, body| {
                if !known.iter().any(|(key, _, _)| key == wanted) {
                    known = holders(config);
                }
                combined(config, &known, parsed, wanted, body)
            })
        } else {
            text(404, "not found")
        };
        let _ = request.respond(response);
    }
    Ok(())
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
    // The slots that hold a share: the device's number for it, the share's number, the key.
    let mut shares: Vec<(u32, u8, Vec<u8>)> = Vec::new();
    for slot in FIRST_SLOT..FIRST_SLOT + SLOTS {
        if let Ok((answer, device::OK)) = device.send(device::PUBLIC_KEY, &slot.to_be_bytes()) {
            if answer.len() == 49 {
                shares.push((slot, answer[48], answer[..48].to_vec()));
            }
        }
    }
    let server =
        Server::http(&config.listen).map_err(|e| format!("listening on {}: {e}", config.listen))?;
    eprintln!(
        "{} keys, {} shares, listening on {}",
        keys.len(),
        shares.len(),
        config.listen
    );

    for mut request in server.incoming_requests() {
        let url = request.url().to_owned();
        let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
        let response = if request.method() == &Method::Get && path == "/upcheck" {
            text(200, "OK")
        } else if request.method() == &Method::Get && path == "/api/v1/eth2/publicKeys" {
            // Only the keys this device signs for alone. A share gives a partial signature,
            // which no validator client can use: it has its own route below.
            let list: Vec<String> = keys
                .iter()
                .map(|k| format!("0x{}", hex::encode(k)))
                .collect();
            text(200, json!(list).to_string()).with_header(json_type())
        } else if request.method() == &Method::Get && path == "/api/v1/shares" {
            let list: Vec<Value> = shares
                .iter()
                .map(|(_, share, key)| json!({ "pubkey": format!("0x{}", hex::encode(key)), "share": share }))
                .collect();
            text(200, json!(list).to_string()).with_header(json_type())
        } else if let (Method::Post, Some(id)) =
            (request.method(), path.strip_prefix("/api/v1/eth2/sign/"))
        {
            answer(&mut request, id, |parsed, wanted, _| {
                let key = keys.iter().position(|k| *k == wanted).ok_or(UnknownKey)?;
                sign(&mut device, config, key as u32, wanted, parsed)
            })
        } else if let (Method::Post, Some(id)) = (
            request.method(),
            path.strip_prefix("/partial/v1/eth2/sign/"),
        ) {
            let share: Option<u8> = query.strip_prefix("share=").and_then(|n| n.parse().ok());
            answer(&mut request, id, |parsed, wanted, _| {
                let (slot, _, _) = shares
                    .iter()
                    .find(|(_, number, key)| key == wanted && share.is_none_or(|s| s == *number))
                    .ok_or(UnknownKey)?;
                sign(&mut device, config, *slot, wanted, parsed)
            })
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
        combine: Vec::new(),
        threshold: 2,
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
            "--combine" => {
                config.combine = value
                    .split(',')
                    .map(|address| address.trim_end_matches('/').to_owned())
                    .collect()
            }
            "--threshold" => {
                config.threshold = value
                    .parse()
                    .ok()
                    .filter(|n| *n >= 1)
                    .ok_or("--threshold: a number from 1 is expected")?
            }
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
    let run = |config: Config| {
        if config.combine.is_empty() {
            serve(&config)
        } else {
            serve_combined(&config)
        }
    };
    if let Err(why) = arguments().and_then(run) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}
