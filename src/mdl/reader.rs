use std::{
    collections::{BTreeMap, HashMap}, future::Future, str::FromStr, sync::Arc
};

use isomdl::{
    definitions::{
        device_request, helpers::{non_empty_map, NonEmptyMap}, x509::{
            self,
            trust_anchor::{PemTrustAnchor, TrustAnchorRegistry},
        }, DeviceAuth, EC2Curve
    },
    presentation::{authentication::AuthenticationStatus as IsoMdlAuthenticationStatus, reader},
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
        reader::SessionManager::establish_session(uri.to_string(), docType, namespaces, registry).map_err(
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
#[derive(uniffi::Enum, Debug)]
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
#[derive(uniffi::Record, Debug)]
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

#[tokio::main]
pub async fn get_jwt(jwt: &str, detached_payload: &str, device_auth: &str) -> (bool, bool)  {
    let header = jwt::decode_header(jwt).unwrap();
    println!("header: {:#?}", header);
    let kid = header.claim("kid").unwrap().as_str().unwrap();
    println!("kid: {:#?}", kid);
    let did = DIDURL::new(&kid).unwrap();
    println!("did: {:#?}", did);

    let url = "https://new-authority-us.dids.aqvc.me/.well-known/did.json";
    let did_document = reqwest::get(url)
                        .await
                        .unwrap()
                        .text()
                        .await;

    let json: serde_json::Value = serde_json::from_str(&did_document.unwrap()).unwrap();
    if let Some(vms) = json["verificationMethod"].as_array() {
        for vm in vms {
            if vm["id"] == "#key_1" {
                let jws = Jws::new(&jwt).unwrap();
                let da_jws = JwsSignature::new(device_auth.as_bytes().to_vec());
                let public_key_jwk = vm["publicKeyJwk"].as_object().unwrap().clone();
                // let jwk: Jwk = Jwk::from_map(public_key_jwk).unwrap();
                // let verifier = ES256.verifier_from_jwk(&jwk).unwrap();
                // let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier).unwrap();
                let key: ssi::jwk::JWK = serde_json::json!(public_key_jwk).try_into().unwrap();
                let decoded_jwt = jws.to_decoded_jwt().unwrap();
                assert!(jws.verify(&key).await.unwrap().is_ok());
                let claims: JWTClaims = decoded_jwt.signing_bytes.payload;// ["payload"]["registered"]["VerifiableCredential"]["credentialSubject"]["id"];
                let registered_claims = serde_json::json!(claims.registered);
                let vc = registered_claims.as_object().unwrap();
                println!("{:#?}", vc);
                let verifiable_credential = vc["vc"].clone();
                let credential_subject = verifiable_credential.as_object().unwrap()["credentialSubject"].clone();
                let id = credential_subject["id"].clone();
                println!("{:#?}", id);
                let key_part = &id.as_str().unwrap()[8..];
                println!("{:#?}", key_part);
                let jwk_values = base64_url::decode(key_part).unwrap();
                println!("{:#?}", jwk_values);
                let binding_key_jwk_val = serde_json::json!(jwk_values);
                //let binding_key_jwk = binding_key_jwk_val.as_object().unwrap();
                //println!("{:#?}", binding_key_jwk);
                println!("{:#?}", key);
                let binding_key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, base64_url::decode("kNYnHB2Mxald17CScUyumLGMUmh_Iy1k0IllLHWJviw").unwrap(), base64_url::decode("YbnKNspahbv7dJbEAHRh-zUQKIDqTTuMxQjv4MQJftY").unwrap()).build();
                
                let signing_bytes = detached_payload.as_bytes();
                let cbor_decoded: DeviceAuth = isomdl::cbor::from_slice(device_auth.as_bytes()).unwrap();
                println!("{:#?}", cbor_decoded);
                
                //let sig = p256::ecdsa::Signature::try_from(DeviceAuth::DeviceSignature((cbor_decoded)));
                assert!(verify_bytes(&coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256), &binding_key, &base64_url::decode(signing_bytes).unwrap(), &base64_url::decode(device_auth).unwrap()).unwrap() == true);
                println!("DONE.");
                // let resolved = DIDJWK.dereference(did_url).await.unwrap();
                // let vm = resolved.content.as_verification_method().unwrap();
                // let binding_key_jwk: ssi::jwk::JWK = serde_json::json!(vm.properties.get("publicKeyMultibase").unwrap()).try_into().unwrap();

                // let binding_key_jws = Jws::new(&device_auth).unwrap();
                // assert!(binding_key_jws.verify(&binding_key_jwk).await.unwrap().is_ok());
                // println!("{:#?}", binding_key_jwk);
                // let did = DIDJWK::generate_url(&key.to_public());
                // let vm_resolver = DIDJWK.into_vm_resolver();
                // let params = VerificationParameters::from_resolver(vm_resolver);
    
                //let validation_result = josekit::jwt::verify(jwt, &key, &header);
                //println!("{:#?}", validation_result);
            }
        }
    }
    //println!("{:#?}", vms);


    // // Setup the DID resolver.
    // let resolver = AnyDidMethod::default();

    // // Dereference the verification method.
    // let handle = tokio::runtime::Handle::current();
    // let vm = resolver
    //     .dereference(did)
    //     .await
    //     .unwrap()
    //     .content
    //     .into_verification_method()
    //     .unwrap();
    // println!("{:#?}", handle);
    // println!("vm: {:#?}", vm);
    //let (payload, header2) = jwt::decode_unsecured(jwt).unwrap();
    
    //println!("jwt: {:#?}", jwt);
    //println!("payload: {:#?}", payload);
    //println!("header2: {:#?}", header);

    //return (payload, header2);
    return (true, true);
}

#[uniffi::export]
pub async fn handle_response(
    state: Arc<MDLSessionManager>,
    response: Vec<u8>,
) -> Result<MDLReaderResponseData, MDLReaderResponseError> {
    let mut state = state.0.clone();
    let validated_response = state.handle_response(&response);
    println!("{:#?}", validated_response);
    if AuthenticationStatus::from(validated_response.issuer_authentication) == AuthenticationStatus::Unchecked {
        println!("Do custom verification.");
        let response = validated_response.response.clone();
        let w3c_document:BTreeMap<String, String> = serde_json::from_value(response.get("w3c_documents").unwrap().clone()).unwrap();
        let jwt = w3c_document.get("jwt");
        let jwt_bytes = jwt.unwrap().as_bytes();
        let jws = w3c_document.get("device_auth");
        let jws_bytes = jws.unwrap().as_bytes();
        let detached_payload = w3c_document.get("device_auth");
        let detached_payload_bytes = jws.unwrap().as_bytes();
        let (issuer_auth, device_auth) = get_jwt(&jwt.unwrap(), &detached_payload.unwrap(), &jws.unwrap());
        println!("{issuer_auth} {device_auth}");
        // MDLReaderResponseError::Generic {
        //     value: format!("Could not serialze errors: {e:?}"),
        // }
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
