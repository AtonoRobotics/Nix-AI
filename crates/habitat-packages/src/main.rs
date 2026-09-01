use ed25519_dalek::VerifyingKey;
use habitat_packages::{
    AdmissionPolicy, BundleSubmission, ExecutableProbe, PackageController, PackageManifest,
    TrustStore,
};
use habitat_uds::{
    connect_with_timeouts, FrameConfig, JsonTransport, ServiceAllowlist, ServiceListener,
    ServicePrincipal, SocketPermissions, StreamTimeouts, DEFAULT_MAX_PAYLOAD,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::net::UnixStream, path::PathBuf, time::Duration};

type Transport = JsonTransport<UnixStream, Value, Value>;

#[derive(Deserialize)]
struct Peer {
    service_id: String,
    uid: u32,
    gid: u32,
}

#[derive(Deserialize)]
struct WireSubmission {
    manifest: PackageManifest,
    bundle: Vec<u8>,
    signature: Vec<u8>,
    provenance: Vec<u8>,
    sbom: Vec<u8>,
    dependency_closure: Vec<String>,
}

#[derive(Deserialize)]
struct AdmissionRequest {
    submission: WireSubmission,
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("publisher key must be 32-byte hex".into());
    }
    let mut result = [0; 32];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "publisher key is not hex".to_string())?;
    }
    Ok(result)
}

fn serve_packages(args: &[String]) -> Result<Value, String> {
    if args.len() != 8 {
        return Err(
            "serve requires socket, state socket, peers, trust, policy, and probe root".into(),
        );
    }
    let peers: Vec<Peer> = serde_json::from_slice(&fs::read(&args[4]).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if peers.len() != 1 || peers[0].service_id != "service:runtime" {
        return Err("package service requires exactly service:runtime".into());
    }
    let principal = ServicePrincipal::new("service:runtime", peers[0].uid, peers[0].gid)
        .map_err(|e| e.to_string())?;
    let listener = ServiceListener::bind(
        &args[2],
        SocketPermissions::new(0o660).map_err(|e| e.to_string())?,
        ServiceAllowlist::new([principal]),
        StreamTimeouts::new(Duration::from_secs(10), Duration::from_secs(10))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let configured: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(&args[5]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut trust = TrustStore::new();
    for (publisher, key) in configured {
        trust.trust(
            &publisher,
            VerifyingKey::from_bytes(&decode_key(&key)?)
                .map_err(|_| "publisher key is invalid".to_string())?,
        );
    }
    let policy: AdmissionPolicy =
        serde_json::from_slice(&fs::read(&args[6]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut controller = PackageController::new(trust);
    let mut probe = ExecutableProbe::new(PathBuf::from(&args[7]), Duration::from_secs(30))?;
    loop {
        let authenticated = match listener.accept() {
            Ok(value) => value,
            Err(error) if error.is_peer_rejection() => continue,
            Err(error) => return Err(error.to_string()),
        };
        let mut transport = authenticated.into_transport::<Value, Value>(
            FrameConfig::new(DEFAULT_MAX_PAYLOAD).map_err(|e| e.to_string())?,
        );
        let request = match transport.receive_request() {
            Ok(value) => value,
            Err(error) if error.is_connection_fault() => continue,
            Err(error) => return Err(error.to_string()),
        };
        if request == Value::String("STATUS".into()) {
            transport
                .send_response(&Value::String(
                    "READY migrations=1 leases_fenced=1 effects_classified=1".into(),
                ))
                .map_err(|e| e.to_string())?;
            continue;
        }
        let request: AdmissionRequest = match serde_json::from_value(request) {
            Ok(value) => value,
            Err(_) => {
                transport
                    .send_response(&json!({"status":"invalid"}))
                    .map_err(|e| e.to_string())?;
                continue;
            }
        };
        let wire = request.submission;
        let signature: [u8; 64] = match wire.signature.try_into() {
            Ok(value) => value,
            Err(_) => {
                transport
                    .send_response(&json!({"status":"invalid"}))
                    .map_err(|e| e.to_string())?;
                continue;
            }
        };
        let submission = BundleSubmission {
            manifest: wire.manifest,
            bundle: wire.bundle,
            signature,
            provenance: wire.provenance,
            sbom: wire.sbom,
            dependency_closure: wire.dependency_closure,
        };
        let manifest = serde_json::to_value(&submission.manifest).map_err(|e| e.to_string())?;
        let verification = match controller.admit_bundle(submission.clone(), &policy, &mut probe) {
            Ok(record) => {
                json!({"manifest":manifest,"manifest_digest":sha(&serde_json::to_vec(&record.manifest).map_err(|e|e.to_string())?),
              "bundle_digest":sha(&submission.bundle),"signature_digest":sha(&submission.signature),
              "provenance_digest":sha(&submission.provenance),"sbom_digest":sha(&submission.sbom),
              "dependency_closure":submission.dependency_closure,"admission_evidence":record.admission_evidence,
              "disposition":"VERIFIED"})
            }
            Err(error) => {
                transport
                    .send_response(&json!({"status":"rejected","reason":format!("{error:?}")}))
                    .map_err(|e| e.to_string())?;
                continue;
            }
        };
        let content_digest = submission.manifest.content_digest.clone();
        let evidence = accepted(
            &args[3],
            json!({"operation":"evidence_put","command_id":format!("package-evidence:{}:{}",submission.manifest.id,content_digest),
          "envelope":{"schema_version":"1","producer":"service:packages","subject":submission.manifest.id,
          "operation":"package.admit","source":content_digest,"payload":verification}}),
        )?;
        let admitted = accepted(
            &args[3],
            json!({"operation":"package_admit","package_id":submission.manifest.id,
          "content_digest":content_digest,"manifest":manifest,"evidence_ref":evidence["evidence_ref"]}),
        )?;
        transport
            .send_response(&json!({"status":"ok","result":admitted}))
            .map_err(|e| e.to_string())?;
    }
}

fn request(socket: &str, value: Value) -> Result<Value, String> {
    let frames = FrameConfig::new(DEFAULT_MAX_PAYLOAD).map_err(|e| e.to_string())?;
    let mut transport: Transport = connect_with_timeouts(
        socket,
        frames,
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .map_err(|e| e.to_string())?;
    transport.send_request(&value).map_err(|e| e.to_string())?;
    transport.receive_response().map_err(|e| e.to_string())
}

fn accepted(socket: &str, value: Value) -> Result<Value, String> {
    let response = request(socket, value)?;
    (response["status"] == "ok")
        .then(|| response["result"].clone())
        .ok_or_else(|| format!("state rejected governed change: {response}"))
}

fn describe() -> Value {
    json!({
        "schema_version": "2.1",
        "component": "packages",
        "abi": "2.1",
        "mode": "peer-authenticated-service"
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("serve") => serve_packages(&args),
        Some("--describe") if args.len() == 2 => Ok(describe()),
        _ => Err("usage: habitat-packages {serve ...|--describe}".into()),
    };
    match result {
        Ok(value) => println!("{}", serde_json::to_string(&value).expect("serializable")),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
