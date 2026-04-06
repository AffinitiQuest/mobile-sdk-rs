use std::collections::HashMap;

use p256::{EncodedPoint, elliptic_curve::generic_array::GenericArray};
use serde_json::Value;

use crate::mdl::reader::{MDLReaderResponseError, W3CVerificationData, fetch_did_document};

/// Cryptosuites we explicitly support.
const SUPPORTED_CRYPTOSUITES: &[&str] = &["ecdsa-jcs-2019"];

/// Recursively sort all JSON object keys in Unicode code-point order for JCS
/// (RFC 8785) canonicalization.
fn jcs_sort(value: &Value) -> Value {
    use std::collections::BTreeMap;
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> =
                map.iter().map(|(k, v)| (k.clone(), jcs_sort(v))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(arr) => Value::Array(arr.iter().map(jcs_sort).collect()),
        other => other.clone(),
    }
}

/// Extract a P-256 verifying key from a DID document for the given
/// verification method URL.
///
/// Supports both `publicKeyJwk` (JWK with `x`/`y` base64url coordinates) and
/// `publicKeyMultibase` (Multikey, base58btc `z`-prefix with `[0x80, 0x24]`
/// multicodec P-256 prefix).
fn extract_p256_verifying_key(
    did_doc: &str,
    vm_url: &str,
) -> Option<p256::ecdsa::VerifyingKey> {
    let doc: Value = serde_json::from_str(did_doc).ok()?;

    let vms = doc.get("verificationMethod").and_then(|v| v.as_array())?;

    // Match by full URL or by fragment suffix (e.g. "#key-0").
    let vm = vms.iter().find(|vm| {
        let id = vm.get("id").and_then(|v| v.as_str()).unwrap_or("");
        id == vm_url || vm_url.ends_with(id)
    })?;

    // publicKeyJwk — standard RFC 7517 EC key with base64url x/y coordinates.
    if let Some(jwk) = vm.get("publicKeyJwk") {
        let x = jwk.get("x").and_then(|v| v.as_str())?;
        let y = jwk.get("y").and_then(|v| v.as_str())?;
        let x_bytes = base64_url::decode(x).ok()?;
        let y_bytes = base64_url::decode(y).ok()?;
        let point = EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&x_bytes),
            GenericArray::from_slice(&y_bytes),
            false,
        );
        return p256::ecdsa::VerifyingKey::from_encoded_point(&point).ok();
    }

    // publicKeyMultibase — Multikey encoding (multibase base58btc, 'z' prefix).
    // Multicodec prefix for P-256 compressed public key: varint [0x80, 0x24].
    if let Some(multibase) = vm.get("publicKeyMultibase").and_then(|v| v.as_str()) {
        if multibase.starts_with('z') {
            let key_bytes = bs58::decode(&multibase[1..]).into_vec().ok()?;
            if key_bytes.len() > 2 && key_bytes[0] == 0x80 && key_bytes[1] == 0x24 {
                let point = EncodedPoint::from_bytes(&key_bytes[2..]).ok()?;
                return p256::ecdsa::VerifyingKey::from_encoded_point(&point).ok();
            }
        }
    }

    None
}

/// Verify an `ecdsa-jcs-2019` Data Integrity proof on a credential.
///
/// Algorithm (per W3C vc-di-ecdsa):
///   proofConfig  = JCS(proof without proofValue)
///   unsecuredDoc = JCS(credential without proof)
///   verifyData   = SHA-256(proofConfig) || SHA-256(unsecuredDoc)
///   signature    = base58btc-decode(proofValue[1..])   // strip 'z' prefix
fn verify_ecdsa_jcs_2019(credential: &Value, verifying_key: &p256::ecdsa::VerifyingKey) -> bool {
    use p256::ecdsa::signature::Verifier;
    use sha2::{Digest, Sha256};

    let Some(proof) = credential.get("proof") else {
        return false;
    };

    // Build proofConfig and unsecuredDocument.
    let mut proof_config = proof.clone();
    if let Some(obj) = proof_config.as_object_mut() {
        obj.remove("proofValue");
    }
    let mut unsigned_doc = credential.clone();
    if let Some(obj) = unsigned_doc.as_object_mut() {
        obj.remove("proof");
    }

    let Ok(canonical_proof) = serde_json::to_string(&jcs_sort(&proof_config)) else {
        return false;
    };
    let Ok(canonical_doc) = serde_json::to_string(&jcs_sort(&unsigned_doc)) else {
        return false;
    };

    println!("[ecdsa_jcs_2019_issuer] canonical_proof_config: {canonical_proof}");
    println!("[ecdsa_jcs_2019_issuer] canonical_document:      {canonical_doc}");

    let mut verify_data = Vec::with_capacity(64);
    verify_data.extend_from_slice(&Sha256::digest(canonical_proof.as_bytes()));
    verify_data.extend_from_slice(&Sha256::digest(canonical_doc.as_bytes()));

    let Some(proof_value) = proof.get("proofValue").and_then(|v| v.as_str()) else {
        return false;
    };
    if !proof_value.starts_with('z') {
        return false;
    }
    let Ok(sig_bytes) = bs58::decode(&proof_value[1..]).into_vec() else {
        return false;
    };

    println!(
        "[ecdsa_jcs_2019_issuer] sig_bytes ({} bytes): {}",
        sig_bytes.len(),
        hex::encode(&sig_bytes)
    );

    let signature = if sig_bytes.len() == 64 {
        match p256::ecdsa::Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        }
    } else {
        match p256::ecdsa::Signature::from_der(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };

    verifying_key.verify(&verify_data, &signature).is_ok()
}

/// Parse and verify an LDP-VC Verifiable Presentation JSON string.
///
/// The `vp_json` argument is the outer Verifiable Presentation produced by the
/// wallet. The inner VC is extracted from `verifiableCredential[0]`. Issuer
/// authentication is verified using `ecdsa-jcs-2019` directly (JCS + P-256
/// ECDSA); the issuer key is resolved from the proof's `verificationMethod`
/// DID via `fetch_did_document`.
///
/// Holder binding (the VP's outer proof) is verified separately in
/// `ldp_vc_device_authentication` inside mobile-isomdl, where the session
/// transcript is available.
#[tokio::main]
pub async fn get_ldp_vc_properties(
    vp_json: &str,
    dids: HashMap<String, String>,
    resolve_dids: bool,
) -> Result<W3CVerificationData, MDLReaderResponseError> {
    // Unwrap the VP to get the inner VC.
    let outer: Value = serde_json::from_str(vp_json).map_err(|_| {
        MDLReaderResponseError::Generic {
            value: "Failed to parse LDP-VC/VP JSON.".to_string(),
        }
    })?;

    let credential: Value = if let Some(vc_array) = outer
        .get("verifiableCredential")
        .and_then(|v| v.as_array())
    {
        vc_array
            .first()
            .cloned()
            .ok_or_else(|| MDLReaderResponseError::Generic {
                value: "Empty verifiableCredential array in VP.".to_string(),
            })?
    } else {
        // Fall back: treat the input as a raw VC (no VP wrapper).
        outer
    };

    let cryptosuite = credential
        .get("proof")
        .and_then(|p| p.get("cryptosuite"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| MDLReaderResponseError::Generic {
            value: "Missing or invalid proof.cryptosuite.".to_string(),
        })?;

    if !SUPPORTED_CRYPTOSUITES.contains(&cryptosuite) {
        return Err(MDLReaderResponseError::Generic {
            value: format!("Unsupported cryptosuite: {cryptosuite}"),
        });
    }

    let verification_method = credential
        .get("proof")
        .and_then(|p| p.get("verificationMethod"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MDLReaderResponseError::Generic {
            value: "Missing proof.verificationMethod.".to_string(),
        })?;
    let did_without_fragment =
        verification_method.split('#').next().unwrap_or(verification_method);
    println!("Resolving issuer key from DID: {did_without_fragment}");

    let issuer_authentication =
        match fetch_did_document(did_without_fragment, &dids, resolve_dids).await {
            Some(doc_text) => {
                println!("DID document: {doc_text}");
                match extract_p256_verifying_key(&doc_text, verification_method) {
                    Some(verifying_key) => verify_ecdsa_jcs_2019(&credential, &verifying_key),
                    None => {
                        println!(
                            "Could not extract P-256 key from DID document for {verification_method}"
                        );
                        false
                    }
                }
            }
            None => {
                println!(
                    "Could not resolve DID document for {did_without_fragment} — issuer authentication skipped."
                );
                false
            }
        };

    let credential_subject = credential
        .get("credentialSubject")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let credential_status = credential.get("credentialStatus").cloned();
    let valid_until = credential.get("validUntil").cloned();

    Ok(W3CVerificationData {
        issuer_authentication,
        response: credential_subject,
        credential_status,
        valid_until,
    })
}
