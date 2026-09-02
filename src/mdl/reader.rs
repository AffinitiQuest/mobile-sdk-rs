use std::{
    collections::{BTreeMap, HashMap}, f64::consts::E, future::Future, str::FromStr, sync::Arc
};

use async_std::stream::Map;
use isomdl::{
    definitions::{
        device_request, helpers::{non_empty_map, NonEmptyMap, NonEmptyVec}, x509::{
            self,
            trust_anchor::{PemTrustAnchor, TrustAnchorRegistry},
        }, DeviceAuth, EC2Curve
    },
    presentation::{authentication::{AuthenticationStatus as IsoMdlAuthenticationStatus, ResponseAuthenticationOutcome}, reader::{self, SessionManager}},
};
use uuid::{uuid, Uuid};
use josekit::{jwk::{alg::ec::EcCurve::P256, Jwk}, jws::JwsHeader, jwt::{self, JwtPayload}, JoseError};
use ssi::{claims::{cose::{coset::{self, iana}, verify_bytes, CoseKey}, jwt::{ClaimSet, InfallibleClaimSet, RegisteredClaimKind, ToDecodedJwt}}, crypto::{algorithm::ES256, ed25519::ed25519::SignatureBytes}, dids::{AnyDidMethod, DIDResolver, DIDURLBuf, DID, DIDURL}, jwk::{ECParams, Params}, prelude::{JWTClaims, VerificationParameters, DIDJWK}};
use reqwest::StatusCode;
use serde_json::json;
use ssi_jws::{Jws, JwsSignature};
use base64_url;
use sha2::{Sha256, Digest};
use crate::reader::coset::CoseKeyBuilder;
//use ssi_claims::ssi_jwt::ToDecodedJwt;

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum MDLReaderSessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Object)]
pub struct MDLSessionManager(reader::SessionManager);

impl std::fmt::Debug for MDLSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Debug for SessionManager not implemented")
    }
}

// Added by Warren Gallagher at AffinitiQuest
#[derive(uniffi::Enum)]
pub enum MDLSessionMode {
    CentralClientMode,
    PeripheralServerMode
}

#[derive(uniffi::Record)]
pub struct MDLReaderSessionData {
    pub state: Arc<MDLSessionManager>,
    uuid: Uuid,
    pub request: Vec<u8>,
    ble_ident: Vec<u8>,
    pub mode: MDLSessionMode, // Added by Warren Gallagher at AffinitiQuest
}

#[uniffi::export]
pub fn establish_session(
    uri: String,
    doc_type: String,
    format: String,
    requested_items: HashMap<String, HashMap<String, bool>>,
    trust_anchor_registry: Option<Vec<String>>,
) -> Result<MDLReaderSessionData, MDLReaderSessionError> {
    let namespaces: Result<BTreeMap<_, NonEmptyMap<_, _>>, non_empty_map::Error> = requested_items
        .into_iter()
        .map(|(doc_type, namespaces)| {
            let namespaces: BTreeMap<_, _> = namespaces.into_iter().collect();
            match namespaces.try_into() {
                Ok(n) => Ok((doc_type, n)),
                Err(e) => Err(e),
            }
        })
        .collect();
    let namespaces = namespaces.map_err(|e| MDLReaderSessionError::Generic {
        value: format!("Unable to build data elements: {e:?}"),
    })?;
    let namespaces: device_request::Namespaces =
        namespaces
            .try_into()
            .map_err(|e| MDLReaderSessionError::Generic {
                value: format!("Unable to build namespaces: {e:?}"),
            })?;

    let registry = TrustAnchorRegistry::from_pem_certificates(
        trust_anchor_registry
            .into_iter()
            .flat_map(|v| v.into_iter())
            .map(|certificate_pem| PemTrustAnchor {
                certificate_pem,
                purpose: x509::trust_anchor::TrustPurpose::Iaca,
            })
            .collect(),
    )
    .map_err(|e| MDLReaderSessionError::Generic {
        value: format!("unable to construct TrustAnchorRegistry: {e:?}"),
    })?;

    let (manager, request, ble_ident) =
        reader::SessionManager::establish_session(uri.to_string(), doc_type, format, namespaces, registry).map_err(
            |e| MDLReaderSessionError::Generic {
                value: format!("unable to establish session: {e:?}"),
            },
        )?;
        
    let manager2 = manager.clone();

    let uuid = manager2.first_peripheral_server_uuid();
    log::info!("{:#?}", uuid);

    // let qr_code = uri.to_string();
    // let device_engagement_bytes = Tag24::<DeviceEngagement>::from_qr_code_uri(&qr_code)
    //     .context("failed to construct QR code")?;
        
    // manager.session_transcript
    //     .0
    //     .as_ref()
    //     .device_retrieval_methods
    //     .as_ref()
    //     .and_then(|ms| {
    //         ms.as_ref()
    //             .iter()
    //             .filter_map(|m| match m {
    //                 _ => Err(MDLReaderSessionError::Generic {
    //                     value: opt.to_string(),
    //                 });
    //                 // DeviceRetrievalMethod::BLE(opt) => {
    //                 //     opt.central_client_mode.as_ref().map(|cc| &cc.uuid)
    //                 // }
    //                 // _ => None,
    //             })
    //             .next()
    //     })
    
    // Based on the BLE options provided in the QR code from the mdl (holder/wallet), it prefers to be:
    //  * use BLE in Peripheral Server Mode OR
    //  * use BLE in Central Client Mode
    // if the mdl specifies both, then the Reader shall use Central Client Mode
    // let manager2 = manager.clone();
    // let uuid  = manager2.first_central_client_uuid();
    // if uuid.is_none() {
    //    let uuid = manager2.first_central_client_uuid();//.first_peripheral_server_uuid();
    //    if uuid.is_none() {
    //        return Err(MDLReaderSessionError::Generic {
    //            value: "the device did not transmit a central client uuid".to_string(),
    //        });
    //    }
    //    else {
    //        return Ok(MDLReaderSessionData {
    //            state: Arc::new(MDLSessionManager(manager)),
    //            request,
    //            ble_ident: ble_ident.to_vec(),
    //            uuid: *uuid.unwrap(),
    //            mode: MDLSessionMode::PeripheralServerMode, // mdl (wallet/holder) wants central client mode, so the Reader should use peripheral server mode
    //        });
    //    }
    // }

    Ok(MDLReaderSessionData {
        state: Arc::new(MDLSessionManager(manager)),
        request,
        ble_ident: ble_ident.to_vec(),
        uuid: *uuid.unwrap(),//uuid!("00006e50-0000-1000-8000-00805f9b34fb"),//Uuid::new_v4(),
        mode: MDLSessionMode::CentralClientMode, // mdl (wallet/holder) wants peripheral server mode, so the Reader should use central client mode
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug, PartialEq)]
pub enum MDLReaderResponseError {
    #[error("Invalid decryption")]
    InvalidDecryption,
    #[error("Invalid parsing")]
    InvalidParsing,
    #[error("Invalid issuer authentication")]
    InvalidIssuerAuthentication,
    #[error("Invalid device authentication")]
    InvalidDeviceAuthentication,
    #[error("{value}")]
    Generic { value: String },
}

// Currently, a lot of information is lost in `isomdl`. For example, bytes are
// converted to strings, but we could also imagine detecting images and having
// a specific enum variant for them.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum MDocItem {
    Text(String),
    Bool(bool),
    Integer(i64),
    ItemMap(HashMap<String, MDocItem>),
    Array(Vec<MDocItem>),
}

impl From<serde_json::Value> for MDocItem {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => unreachable!("No null allowed in namespaces"),
            serde_json::Value::Bool(b) => Self::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Integer(i)
                } else {
                    unreachable!("Only integers allowed in namespaces")
                }
            }
            serde_json::Value::String(s) => Self::Text(s),
            serde_json::Value::Array(a) => {
                Self::Array(a.iter().map(|o| Into::<Self>::into(o.clone())).collect())
            }
            serde_json::Value::Object(m) => Self::ItemMap(
                m.iter()
                    .map(|(k, v)| (k.clone(), Into::<Self>::into(v.clone())))
                    .collect(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum AuthenticationStatus {
    Valid,
    Invalid,
    Unchecked,
}

impl From<IsoMdlAuthenticationStatus> for AuthenticationStatus {
    fn from(internal: IsoMdlAuthenticationStatus) -> Self {
        match internal {
            IsoMdlAuthenticationStatus::Valid => AuthenticationStatus::Valid,
            IsoMdlAuthenticationStatus::Invalid => AuthenticationStatus::Invalid,
            IsoMdlAuthenticationStatus::Unchecked => AuthenticationStatus::Unchecked,
        }
    }
}
#[derive(uniffi::Record, Clone, Debug)]
pub struct MDLReaderResponseData {
    state: Arc<MDLSessionManager>,
    /// Contains the namespaces for the mDL directly, without top-level doc types
    verified_response: HashMap<String, HashMap<String, MDocItem>>,
    /// Outcome of issuer authentication.
    pub issuer_authentication: AuthenticationStatus,
    /// Outcome of device authentication.
    pub device_authentication: AuthenticationStatus,
    /// Errors that occurred during response processing.
    pub errors: Option<String>,
    /// Decoded OID4VCI CredentialIssuerMetadata JSON payload, if the wallet included signed metadata.
    pub signed_issuer_metadata: Option<String>,
    /// Whether the signed issuer metadata JWS signature was verified. None = not present or not attempted.
    pub issuer_metadata_signature_verified: Option<bool>,
}

pub struct W3CVerificationData {
    pub issuer_authentication: bool,
    pub issuer_auth_failure_reason: Option<String>,
    pub response: serde_json::Value,
    pub credential_status: Option<serde_json::Value>,
    pub valid_until: Option<serde_json::Value>
}

/// Decode and verify SD-JWT disclosures against the `_sd` hash commitments in the issuer-signed
/// payload.
///
/// For each `~`-separated disclosure string D (everything after the base JWT):
///   1. Compute `SHA-256(D)` and base64url-encode it.
///   2. Verify the hash appears in an `_sd` array inside the VC payload — if the hash is not
///      committed to by the issuer the disclosure is silently dropped (prevents claim injection).
///   3. Decode D from base64url, parse as `[salt, name, value]`, and add `name → value` to the
///      output map.
///
/// Returns an empty map for plain JWT-VCs (no `~` separators / no `_sd` hashes).
fn decode_sd_jwt_disclosures(
    jwt: &str,
    vc: &serde_json::Map<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    let parts: Vec<&str> = jwt.split('~').collect();
    if parts.len() <= 1 {
        return HashMap::new();
    }

    // Collect all _sd hash commitments from known locations in the VC payload.
    let mut sd_hashes: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Location 1: vc.credentialSubject._sd
    if let Some(serde_json::Value::Object(cs)) = vc.get("credentialSubject") {
        if let Some(serde_json::Value::Array(sd)) = cs.get("_sd") {
            for hash in sd {
                if let Some(h) = hash.as_str() {
                    sd_hashes.insert(h.to_string());
                }
            }
        }
    }

    // Location 2: vc._sd (top-level inside the vc claim)
    if let Some(serde_json::Value::Array(sd)) = vc.get("_sd") {
        for hash in sd {
            if let Some(h) = hash.as_str() {
                sd_hashes.insert(h.to_string());
            }
        }
    }

    // No hash commitments found — cannot verify any disclosure, return empty.
    if sd_hashes.is_empty() {
        return HashMap::new();
    }

    let mut claims = HashMap::new();

    // Disclosures are parts[1..]; the last segment may be a KB-JWT (contains two dots).
    for disclosure in &parts[1..] {
        if disclosure.is_empty() {
            continue;
        }

        // Step 1: verify the disclosure hash is committed to by the issuer.
        let hash_bytes = Sha256::digest(disclosure.as_bytes());
        let hash_b64 = base64_url::encode(&hash_bytes);
        if !sd_hashes.contains(&hash_b64) {
            // Not committed to — skip to prevent claim injection.
            continue;
        }

        // Step 2: decode and parse as [salt, name, value].
        if let Ok(decoded) = base64_url::decode(disclosure) {
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_slice(&decoded) {
                if arr.len() == 3 {
                    if let Some(name) = arr[1].as_str() {
                        claims.insert(name.to_string(), arr[2].clone());
                    }
                }
            }
        }
    }

    claims
}

pub fn get_jwt_properties(jwt: &str) -> Result<W3CVerificationData, MDLReaderResponseError> {
    // SD-JWT format: base_jwt~disclosure1~...~kb_jwt — parse only the base JWT.
    let base_jwt = jwt.split('~').next().unwrap_or(jwt);
    let jws = Jws::new(base_jwt).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse JWT.".to_string() })?;
    let decoded_jwt = jws.to_decoded_jwt().map_err(|_| MDLReaderResponseError::Generic { value: "Failed to get decoded JWT.".to_string() })?;
    let claims: JWTClaims = decoded_jwt.signing_bytes.payload;
    // Serialize the full claims struct (registered + private are both #[serde(flatten)]),
    // so the resulting object contains all JWT claims including "vc", "vct", "cnf", "_sd", etc.
    let all_claims = serde_json::to_value(&claims).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to serialize claims.".to_string() })?;
    let verifiable_credential = all_claims.as_object().ok_or(MDLReaderResponseError::Generic { value: "Failed to parse claims.".to_string() })?;

    // Support two credential structures:
    //  - VCDM 1.1 JWT-VC: claims nested under "vc.credentialSubject"
    //  - SD-JWT VC (draft-ietf-oauth-sd-jwt-vc): claims at the top level, typed via "vct"
    let (mut credential_subject, credential_status, valid_until) =
        if let Some(vc) = verifiable_credential.get("vc").and_then(|v| v.as_object()) {
            let cs = vc["credentialSubject"].clone();
            let status = vc.get("credentialStatus").cloned();
            let until = vc.get("validUntil").cloned();
            (cs, status, until)
        } else {
            // SD-JWT VC: filter out JWT infrastructure claims; the rest are credential claims.
            const RESERVED: &[&str] = &[
                "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
                "cnf", "vct", "_sd", "_sd_alg", "status", "type",
            ];
            let cs: serde_json::Map<String, serde_json::Value> = verifiable_credential
                .iter()
                .filter(|(k, _)| !RESERVED.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let status = verifiable_credential.get("status").cloned();
            let until = verifiable_credential.get("exp").cloned();
            (serde_json::Value::Object(cs), status, until)
        };

    // For SD-JWTs, decode verified disclosures and merge into the credential subject.
    // Pass the full JWT payload so _sd hashes at the top level are found.
    let disclosed_claims = decode_sd_jwt_disclosures(jwt, verifiable_credential);
    if !disclosed_claims.is_empty() {
        if let Some(obj) = credential_subject.as_object_mut() {
            for (key, value) in disclosed_claims {
                obj.insert(key, value);
            }
        }
    }

    return Ok(W3CVerificationData {
                    issuer_authentication: false,
                    issuer_auth_failure_reason: None,
                    response: credential_subject,
                    credential_status,
                    valid_until,
    });
}

/// Fetch a DID document for a `did:web:` DID, applying the trust/resolve policy.
///
/// - `did_without_fragment`: e.g. `did:web:example.com`
/// - `dids`: pre-trusted DID documents keyed by DID string
/// - `resolve_dids`: if true, prefer the live-fetched document over the trusted one;
///   if false, only use the trusted document (live fetch is still attempted so the
///   caller can tell whether the DID exists, but its content is ignored)
///
/// Returns `None` when no document is available (caller should treat as unverified).
pub async fn fetch_did_document(
    did_without_fragment: &str,
    dids: &HashMap<String, String>,
    resolve_dids: bool,
) -> Option<String> {
    let trusted = dids.get(did_without_fragment).cloned();

    if !did_without_fragment.starts_with("did:web:") {
        return trusted;
    }
    let domain = &did_without_fragment[8..];
    let url = format!("https://{domain}/.well-known/did.json");
    log::info!("Fetching DID document from: {url}");

    let fetched_text = match reqwest::get(&url).await {
        Ok(response) => response.text().await.ok(),
        Err(_) => None,
    };

    match (resolve_dids, fetched_text, trusted) {
        (true, Some(fetched), _) => Some(fetched),
        (true, None, trusted) => trusted,
        (false, _, trusted) => trusted,
    }
}

#[tokio::main]
pub async fn get_jwt(jwt: &str, dids: HashMap<String, String>, resolve_dids: bool) -> Result<W3CVerificationData, MDLReaderResponseError>  {
    // SD-JWT format: base_jwt~disclosure1~...~kb_jwt — parse only the base JWT.
    let base_jwt = jwt.split('~').next().unwrap_or(jwt);
    let header = jwt::decode_header(base_jwt).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to decode JWT header.".to_string() })?;
    // SD-JWT VC: issuer public key is embedded in the "jwk" header claim (no DID resolution needed)
    if let Some(jwk_val) = header.claim("jwk") {
        let jwk: ssi::jwk::JWK = serde_json::from_value(jwk_val.clone())
            .map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse JWK from header.".to_string() })?;
        let jws = Jws::new(base_jwt).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse JWT for verification.".to_string() })?;
        let verification_result = jws.verify(&jwk).await.map_err(|_| MDLReaderResponseError::Generic { value: "Failed to verify credential signature.".to_string() })?.is_ok();
        let mut jwt_info: W3CVerificationData = get_jwt_properties(jwt)?;
        jwt_info.issuer_authentication = verification_result;
        return Ok(jwt_info);
    }

    // JWT-VC: issuer key referenced via "kid" DID URL
    let kid = match header.claim("kid").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return get_jwt_properties(jwt),
    };
    let did = DIDURL::new(&kid).unwrap();
    let without_fragment = did.without_fragment().0;
    let fragment = did.without_fragment().1.ok_or(MDLReaderResponseError::Generic { value: "Failed to get key fragment from DID.".to_string() })?;

    let final_did_document = match fetch_did_document(without_fragment.as_str(), &dids, resolve_dids).await {
        Some(doc) => doc,
        None => return get_jwt_properties(jwt),
    };

    let json: serde_json::Value = serde_json::from_str(&final_did_document).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse DID Document.".to_string() })?;
    if let Some(vms) = json["verificationMethod"].as_array() {
        for vm in vms {
            let fragment_string = fragment.as_str();
            log::info!("{:#?}", fragment_string);
            let key_id = format!("#{fragment_string}");
            if vm["id"] == key_id {
                let jws = Jws::new(base_jwt).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse JWT for verification.".to_string() })?;
                let public_key_jwk = vm["publicKeyJwk"].as_object().ok_or(MDLReaderResponseError::Generic { value: "Failed to get publicKeyJWK from DID.".to_string() })?;
                let key: ssi::jwk::JWK = serde_json::json!(public_key_jwk).try_into().map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse Issuer JWK from DID Document.".to_string() })?;
                let verification_result = jws.verify(&key).await.map_err(|_| MDLReaderResponseError::Generic { value: "Failed to verify credential signature.".to_string() })?.is_ok();
                let mut jwt_info: W3CVerificationData = get_jwt_properties(jwt)?;
                jwt_info.issuer_authentication = verification_result;
                log::info!("Credential Status: {:#?}", jwt_info.credential_status);
                return Ok(jwt_info)
            }
        }
    }
    return Ok(W3CVerificationData {
        issuer_authentication: false,
        issuer_auth_failure_reason: None,
        response: serde_json::to_value(serde_json::Map::new()).unwrap(),
        credential_status: None,
        valid_until: None
    });
}

/// Validate that the signed issuer metadata field is a well-formed compact JWS and pass the raw
/// JWS string to the JS layer. Signature verification is handled entirely in JS via
/// FederationTrustService using @pagopa/io-react-native-jwt.
/// Returns (raw_jws, None) — the bool slot is always None since JS owns verification.
pub fn verify_metadata_jws(
    jws_str: &str,
    _dids: &HashMap<String, String>,
    _resolve_dids: bool,
) -> (Option<String>, Option<bool>) {
    let parts: Vec<&str> = jws_str.splitn(3, '.').collect();
    if parts.len() != 3 {
        log::warn!("[verify_metadata_jws] malformed JWS — not 3 parts");
        return (None, None);
    }
    log::info!("[verify_metadata_jws] passing raw JWS to JS layer, length={}", jws_str.len());
    (Some(jws_str.to_string()), None)
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct VerificationResponse {
    responses: Vec<MDLReaderResponseData>
}

impl FromIterator<MDLReaderResponseData> for VerificationResponse {
        fn from_iter<T: IntoIterator<Item = MDLReaderResponseData>>(iter: T) -> Self {
            let mut items: Vec<MDLReaderResponseData> = Vec::new();
            for i in iter {
                items.push(i);
            }
            VerificationResponse {
                responses: items
            }
        }
    }

pub fn get_verified_response(
    state: SessionManager,
    validated_response_object: ResponseAuthenticationOutcome,
    dids: HashMap<String, String> ,
    resolve_dids: bool
) -> Result<MDLReaderResponseData, MDLReaderResponseError> {
    log::info!("[get_verified_response] signed_issuer_metadata present: {}", validated_response_object.signed_issuer_metadata.is_some());
    let mut validated_response = validated_response_object.clone();
    if AuthenticationStatus::from(validated_response.issuer_authentication) == AuthenticationStatus::Unchecked {
        log::info!("Do W3CJWT verification.");
        let response = validated_response.response.clone();
        let w3c_documents = response.get("document").ok_or(MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
        let w3c_document:BTreeMap<String, String> = serde_json::from_value(w3c_documents.clone()).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
        let issuer_authentication = if let Some(ldp_vc) = w3c_document.get("ldp_vc") {
            log::info!("LDP-VC credential — verifying Data Integrity proof.");
            crate::mdl::ldp_vc::get_ldp_vc_properties(ldp_vc, dids.clone(), resolve_dids)?
        } else {
            let jwt = w3c_document.get("jwt").ok_or(MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
            get_jwt(jwt, dids.clone(), resolve_dids)?
        };
        let verification_result = issuer_authentication.issuer_authentication;
        if(verification_result) {
            validated_response.issuer_authentication = IsoMdlAuthenticationStatus::Valid;
            validated_response.response.clear();
        } else {
            validated_response.issuer_authentication = IsoMdlAuthenticationStatus::Invalid;
            let reason = issuer_authentication.issuer_auth_failure_reason
                .unwrap_or_else(|| "Failed to authenticate issuer signature.".to_string());
            validated_response.errors.insert("Issuer Validation Error".to_string(), serde_json::json!(reason));
        }

        validated_response.response.insert("all".to_string(), issuer_authentication.response);
        if issuer_authentication.credential_status != None {
            log::info!("Credential status present.");
            validated_response.response.insert("credentialStatus".to_string(), issuer_authentication.credential_status.unwrap());
        }

        if issuer_authentication.valid_until != None {
            log::info!("Valid until present.");
            let mut valid_until_object = HashMap::new();
            valid_until_object.insert("validUntil".to_string(), issuer_authentication.valid_until.unwrap());
            let valid_until_value = serde_json::to_value(&valid_until_object).unwrap();
            validated_response.response.insert("validUntil".to_string(), valid_until_value);
        }
    }

    let errors = if !validated_response.errors.is_empty() {
        Some(
            serde_json::to_string(&validated_response.errors).map_err(|e| {
                MDLReaderResponseError::Generic {
                    value: format!("Could not serialze errors: {e:?}"),
                }
            })?,
        )
    } else {
        None
    };
    log::info!("{:#?}", errors);
    let verified_response: Result<HashMap<String, HashMap<String, MDocItem>>, MDLReaderResponseError> = validated_response
        .response
        .into_iter()
        .map(|(namespace, items)| {
            if let Some(items) = items.as_object() {
                let items = items
                    .iter()
                    .map(|(item, value)| (item.clone(), value.clone().into()))
                    .collect();
                Ok((namespace.to_string(), items))
            } else {
                Err(MDLReaderResponseError::Generic {
                    value: format!("Items not object, instead: {items:#?}"),
                })
            }
        })
        .collect();
    let mut verified_response = verified_response.map_err(|e| MDLReaderResponseError::Generic {
        value: format!("Unable to parse response: {e:?}"),
    })?;

    // Surface the leaf certificate's identity for CRL-based revocation checking, via a
    // synthetic non-ISO namespace rather than a new top-level struct field - "x509" can't
    // collide with a real mdoc namespace (those are reverse-DNS, e.g. org.iso.18013.5.1).
    if validated_response.leaf_certificate_serial_number.is_some()
        || validated_response.leaf_certificate_crl_distribution_point.is_some()
    {
        let mut x509_entry = HashMap::new();
        if let Some(serial) = validated_response.leaf_certificate_serial_number.clone() {
            x509_entry.insert("leafCertificateSerialNumber".to_string(), MDocItem::Text(serial));
        }
        if let Some(cdp) = validated_response.leaf_certificate_crl_distribution_point.clone() {
            x509_entry.insert("leafCertificateCrlDistributionPoint".to_string(), MDocItem::Text(cdp));
        }
        verified_response.insert("x509".to_string(), x509_entry);
    }
    let (signed_issuer_metadata, issuer_metadata_signature_verified) =
        match validated_response.signed_issuer_metadata.as_deref() {
            Some(jws) => {
                log::info!("[get_verified_response] passing metadata JWS to JS, length={}", jws.len());
                verify_metadata_jws(jws, &dids, resolve_dids)
            },
            None => {
                log::info!("[get_verified_response] no signed_issuer_metadata in validated_response");
                (None, None)
            },
        };
    log::info!("[get_verified_response] final: signed_issuer_metadata present={}, verified={:?}", signed_issuer_metadata.is_some(), issuer_metadata_signature_verified);

    Ok(MDLReaderResponseData {
        state: Arc::new(MDLSessionManager(state)),
        verified_response,
        issuer_authentication: AuthenticationStatus::from(validated_response.issuer_authentication),
        device_authentication: AuthenticationStatus::from(validated_response.device_authentication),
        errors,
        signed_issuer_metadata,
        issuer_metadata_signature_verified,
    })
}

#[uniffi::export]
pub async fn handle_response(
    state: Arc<MDLSessionManager>,
    response: Vec<u8>,
    dids: HashMap<String, String>,
    resolve_dids: bool
) -> Result<VerificationResponse, MDLReaderResponseError> {
    let mut state = state.0.clone();
    let validated_responses = state.handle_response(&response);
    log::info!("Number of parsed responses: {:#?}", validated_responses.responses.len().to_string());
    if validated_responses.responses.len() == 0 {
        return Err(MDLReaderResponseError::Generic { value: "No valid credentials shared.".to_string() });
    }

    let verified_responses: VerificationResponse = validated_responses.responses
                                .into_iter()
                                .map(|validated_response| {
                                    let verified_response = get_verified_response(state.clone(), validated_response.clone(), dids.clone(), resolve_dids);
                                    verified_response.unwrap()
                                })
                                .collect();
    Ok(verified_responses)
}
