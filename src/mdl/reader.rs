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
    docType: String,
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
        reader::SessionManager::establish_session(uri.to_string(), docType, format, namespaces, registry).map_err(
            |e| MDLReaderSessionError::Generic {
                value: format!("unable to establish session: {e:?}"),
            },
        )?;
        
    let manager2 = manager.clone();

    let uuid = manager2.first_peripheral_server_uuid();
    println!("{:#?}", uuid);

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
}

pub struct W3CVerificationData {
    pub issuer_authentication: bool,
    pub response: serde_json::Value,
    pub credential_status: Option<serde_json::Value>,
    pub valid_until: Option<serde_json::Value>
}

#[tokio::main]
pub async fn get_jwt(jwt: &str, dids: HashMap<String, String>, resolve_dids: bool) -> Result<W3CVerificationData, MDLReaderResponseError>  {
    let header = jwt::decode_header(jwt).unwrap();
    println!("header: {:#?}", header);
    let kid = header.claim("kid").unwrap().as_str().unwrap();
    println!("kid: {:#?}", kid);
    let did = DIDURL::new(&kid).unwrap();
    let without_fragment = did.without_fragment().0;
    println!("FRAGMENT: {:#?}", without_fragment.to_string());
    let fragment = did.without_fragment().1.ok_or(MDLReaderResponseError::Generic { value: "Failed to get key fragment from DID.".to_string() })?;
    let domain = &without_fragment[8..];
    println!("did: {:#?}", domain);
    
    let trusted_did_document = dids.get(without_fragment.as_str());
    println!("{:#?}", trusted_did_document);
    let url = format!("https://{domain}/.well-known/did.json");
    println!("{:#?}", url);
    let did_document = reqwest::get(url)
                        .await;

    let final_did_document = match did_document {
        Ok(resolved_did_document) => {
            let resolved_did_document_text = match resolved_did_document.text().await {
                Ok(resolved_did_document_text_value) => {
                    resolved_did_document_text_value
                }
                Err(e) => {
                    return Err(MDLReaderResponseError::Generic { value: "Failed to parse DID document.".to_string() });
                }
            };

            if resolve_dids { 
                resolved_did_document_text
            } else { 
                if trusted_did_document.is_none() {
                    return Err(MDLReaderResponseError::Generic { value: "No local DID stored.".to_string() });
                } else {
                    trusted_did_document.unwrap().clone()
                }
            }
        }
        Err(e) => {
            if trusted_did_document.is_none() {
                return Err(MDLReaderResponseError::Generic { value: without_fragment.to_string() });
            } else {
                trusted_did_document.unwrap().clone()
            }
        }
    };
    
    let json: serde_json::Value = serde_json::from_str(&final_did_document).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse DID Document.".to_string() })?;
    if let Some(vms) = json["verificationMethod"].as_array() {
        for vm in vms {
            let fragment_string = fragment.as_str();
            println!("{:#?}", fragment_string);
            let key_id = format!("#{fragment_string}");
            if vm["id"] == key_id {
                let jws = Jws::new(&jwt).unwrap();
                let public_key_jwk = vm["publicKeyJwk"].as_object().ok_or(MDLReaderResponseError::Generic { value: "Failed to get publicKeyJWK from DID.".to_string() })?;
                let key: ssi::jwk::JWK = serde_json::json!(public_key_jwk).try_into().map_err(|_| MDLReaderResponseError::Generic { value: "Failed to parse Issuer JWK from DID Document.".to_string() })?;
                let decoded_jwt = jws.to_decoded_jwt().map_err(|_| MDLReaderResponseError::Generic { value: "Failed to get decoded JWT.".to_string() })?;
                let verification_result = jws.verify(&key).await.map_err(|_| MDLReaderResponseError::Generic { value: "Failed to verify credential signature.".to_string() })?.is_ok();
                let claims: JWTClaims = decoded_jwt.signing_bytes.payload;// ["payload"]["registered"]["VerifiableCredential"]["credentialSubject"]["id"];
                let registered_claims = serde_json::json!(claims.registered);
                let verifiable_credential = registered_claims.as_object().ok_or(MDLReaderResponseError::Generic { value: "Failed to parse claims.".to_string() })?;
                let vc = verifiable_credential["vc"].as_object().ok_or(MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
                let credential_subject = vc["credentialSubject"].clone();
                let credential_status = vc.get("credentialStatus");
                let valid_until = vc.get("validUntil");
                println!("Credential Status: {:#?}", credential_status);
                return Ok(W3CVerificationData {
                    issuer_authentication: verification_result, 
                    response: credential_subject.clone(),
                    credential_status: credential_status.cloned(),
                    valid_until: valid_until.cloned()
                })
            }
        }
    }
    return Ok(W3CVerificationData {
        issuer_authentication: false, 
        response: serde_json::to_value(serde_json::Map::new()).unwrap(),
        credential_status: None,
        valid_until: None
    });
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
    println!("{:#?}", validated_response_object);
    let mut validated_response = validated_response_object.clone();
    if AuthenticationStatus::from(validated_response.issuer_authentication) == AuthenticationStatus::Unchecked {
        println!("Do W3CJWT verification.");
        let response = validated_response.response.clone();
        let w3c_documents = response.get("w3c_documents").ok_or(MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
        let w3c_document:BTreeMap<String, String> = serde_json::from_value(w3c_documents.clone()).map_err(|_| MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
        let jwt = w3c_document.get("jwt").ok_or(MDLReaderResponseError::Generic { value: "Failed to retrieve claims.".to_string() })?;
        println!("{:#?}", jwt);
        let issuer_authentication = get_jwt(&jwt, dids, resolve_dids).unwrap();
        let verification_result = issuer_authentication.issuer_authentication;
        if(verification_result) {
            validated_response.issuer_authentication = IsoMdlAuthenticationStatus::Valid;
            validated_response.response.clear();
            validated_response.response.insert("all".to_string(), issuer_authentication.response);
            if issuer_authentication.credential_status != None {
                println!("Credential status present.");
                validated_response.response.insert("credentialStatus".to_string(), issuer_authentication.credential_status.unwrap());
            }

            if issuer_authentication.valid_until != None {
                println!("Valid until present.");
                validated_response.response.insert("validUntil".to_string(), issuer_authentication.valid_until.unwrap());
            }
        } else {
            validated_response.issuer_authentication = IsoMdlAuthenticationStatus::Invalid;
            validated_response.errors.insert("Issuer Validation Error".to_string(), serde_json::json!("Failed to authenticate issuer signature.".to_string()));
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
    println!("{:#?}", errors);
    let verified_response: Result<_, _> = validated_response
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
    let verified_response = verified_response.map_err(|e| MDLReaderResponseError::Generic {
        value: format!("Unable to parse response: {e:?}"),
    })?;
    Ok(MDLReaderResponseData {
        state: Arc::new(MDLSessionManager(state)),
        verified_response,
        issuer_authentication: AuthenticationStatus::from(validated_response.issuer_authentication),
        device_authentication: AuthenticationStatus::from(validated_response.device_authentication),
        errors,
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
    println!("Number of parsed responses: {:#?}", validated_responses.responses.len().to_string());
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
