use super::error::OID4VPError;
use super::permission_request::*;
use crate::common::*;
use crate::credential::*;
use crate::vdc_collection::VdcCollection;

use std::sync::Arc;

use openid4vp::core::authorization_request::parameters::ClientIdScheme;
use openid4vp::core::credential_format::{ClaimFormatDesignation, ClaimFormatPayload};
use openid4vp::core::presentation_definition::PresentationDefinition;
use openid4vp::{
    core::{
        authorization_request::{
            parameters::ResponseMode,
            verification::{did::verify_with_resolver, RequestVerifier},
            AuthorizationRequestObject,
        },
        metadata::WalletMetadata,
    },
    wallet::Wallet as OID4VPWallet,
};
use ssi::dids::DIDWeb;
use ssi::dids::VerificationMethodDIDResolver;
use ssi::prelude::AnyJwkMethod;
use uniffi::deps::{anyhow, log};

/// A Holder is an entity that possesses one or more Verifiable Credentials.
/// The Holder is typically the subject of the credentials, but not always.
/// The Holder has the ability to generate Verifiable Presentations from
/// these credentials and share them with Verifiers.
#[derive(Debug, uniffi::Object)]
pub struct Holder {
    /// An atomic reference to the VDC collection.
    pub(crate) vdc_collection: Option<Arc<VdcCollection>>,

    /// Metadata about the holder.
    pub(crate) metadata: WalletMetadata,

    /// HTTP Request Client
    pub(crate) client: openid4vp::core::util::ReqwestClient,

    /// A list of trusted DIDs.
    #[allow(dead_code)]
    pub(crate) trusted_dids: Vec<String>,

    /// Provide optional credentials to the holder instance.
    pub(crate) provided_credentials: Option<Vec<Arc<ParsedCredential>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Holder {
    /// Uses VDC collection to retrieve the credentials for a given presentation definition.
    #[uniffi::constructor]
    pub async fn new(
        vdc_collection: Arc<VdcCollection>,
        trusted_dids: Vec<String>,
    ) -> Result<Arc<Self>, OID4VPError> {
        let client = openid4vp::core::util::ReqwestClient::new()
            .map_err(|e| OID4VPError::HttpClientInitialization(format!("{e:?}")))?;

        Ok(Arc::new(Self {
            client,
            vdc_collection: Some(vdc_collection),
            metadata: Self::metadata()?,
            trusted_dids,
            provided_credentials: None,
        }))
    }

    /// Construct a new holder with provided credentials
    /// instead of a VDC collection.
    ///
    /// This constructor will use the provided credentials for the presentation,
    /// instead of searching for credentials in the VDC collection.
    #[uniffi::constructor]
    pub async fn new_with_credentials(
        provided_credentials: Vec<Arc<ParsedCredential>>,
        trusted_dids: Vec<String>,
    ) -> Result<Arc<Self>, OID4VPError> {
        let client = openid4vp::core::util::ReqwestClient::new()
            .map_err(|e| OID4VPError::HttpClientInitialization(format!("{e:?}")))?;

        Ok(Arc::new(Self {
            client,
            vdc_collection: None,
            metadata: Self::metadata()?,
            trusted_dids,
            provided_credentials: Some(provided_credentials),
        }))
    }

    /// Given an authorization request URL, return a permission request,
    /// which provides a list of requested credentials and requested fields
    /// that align with the presentation definition of the request.
    ///
    /// This will fetch the presentation definition from the verifier.
    pub async fn authorization_request(
        &self,
        url: Url,
        // Callback here to allow for review of untrusted DIDs.
    ) -> Result<Arc<PermissionRequest>, OID4VPError> {
        let request = self
            .validate_request(url)
            .await
            .map_err(|e| OID4VPError::RequestValidation(format!("{e:?}")))?;

        match request.response_mode() {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                self.permission_request(request).await
            }
            ResponseMode::Unsupported(mode) => {
                Err(OID4VPError::UnsupportedResponseMode(mode.to_owned()))
            }
        }
    }

    pub async fn submit_permission_response(
        &self,
        response: Arc<PermissionResponse>,
    ) -> Result<Option<Url>, OID4VPError> {
        self.submit_response(
            response.authorization_request.clone(),
            response.authorization_response()?,
        )
        .await
        .map_err(|e| OID4VPError::ResponseSubmission(format!("{e:?}")))
    }
}

// Internal methods for the Holder.
impl Holder {
    /// Return the static metadata for the holder.
    ///
    /// This method is used to initialize the metadata for the holder.
    pub(crate) fn metadata() -> Result<WalletMetadata, OID4VPError> {
        let mut metadata = WalletMetadata::openid4vp_scheme_static();

        // Insert support for the VCDM2 SD JWT format.
        metadata.vp_formats_supported_mut().0.insert(
            ClaimFormatDesignation::Other("vcdm2_sd_jwt".into()),
            ClaimFormatPayload::AlgValuesSupported(vec!["ES256".into()]),
        );

        metadata
            // Insert support for the DID client ID scheme.
            .add_client_id_schemes_supported(ClientIdScheme::Did)
            .map_err(|e| OID4VPError::MetadataInitialization(format!("{e:?}")))?;

        Ok(metadata)
    }

    /// This will return all the credentials that match the presentation definition.
    async fn search_credentials_vs_presentation_definition(
        &self,
        definition: &PresentationDefinition,
    ) -> Result<Vec<Arc<ParsedCredential>>, OID4VPError> {
        let credentials = match &self.provided_credentials {
            // Use a pre-selected list of credentials if provided.
            Some(credentials) => credentials.to_owned(),
            None => match &self.vdc_collection {
                None => vec![],
                Some(vdc_collection) => vdc_collection
                    .all_entries()?
                    .into_iter()
                    .filter_map(|id| {
                        vdc_collection
                            .get(id)
                            .ok()
                            .flatten()
                            .and_then(|cred| cred.try_into_parsed().ok())
                    })
                    .collect::<Vec<Arc<ParsedCredential>>>(),
            },
        }
        .into_iter()
        .filter_map(
            |cred| match cred.check_presentation_definition(definition) {
                true => Some(cred),
                false => None,
            },
        )
        .collect::<Vec<Arc<ParsedCredential>>>();

        Ok(credentials)
    }

    // Internal method for returning the `PermissionRequest` for an oid4vp request.
    async fn permission_request(
        &self,
        request: AuthorizationRequestObject,
    ) -> Result<Arc<PermissionRequest>, OID4VPError> {
        // Resolve the presentation definition.
        let presentation_definition = request
            .resolve_presentation_definition(self.http_client())
            .await
            .map_err(|e| OID4VPError::PresentationDefinitionResolution(format!("{e:?}")))?
            .into_parsed();

        let credentials = self
            .search_credentials_vs_presentation_definition(&presentation_definition)
            .await?;

        Ok(PermissionRequest::new(
            presentation_definition.clone(),
            credentials.clone(),
            request,
        ))
    }
}

#[async_trait::async_trait]
impl RequestVerifier for Holder {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        log::debug!("Verifying DID request.");

        let resolver: VerificationMethodDIDResolver<DIDWeb, AnyJwkMethod> =
            VerificationMethodDIDResolver::new(DIDWeb);

        // NOTE: This is temporary solution that will allow any DID to be
        // trusted. This will be replaced by the trust manager in the future.
        let client_id = decoded_request.client_id();

        verify_with_resolver(
            &self.metadata,
            decoded_request,
            request_jwt,
            Some(&[client_id.0.clone()]),
            &resolver,
        )
        .await?;

        Ok(())
    }
}

impl OID4VPWallet for Holder {
    type HttpClient = openid4vp::core::util::ReqwestClient;

    fn http_client(&self) -> &Self::HttpClient {
        &self.client
    }

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vcdm2_sd_jwt::VCDM2SdJwt;

    // NOTE: This test requires the `companion` service to be running and
    // available at localhost:3000.
    //
    // See: https://github.com/spruceid/companion/pull/1
    #[ignore]
    #[tokio::test]
    async fn test_oid4vp_url() -> Result<(), Box<dyn std::error::Error>> {
        let example_sd_jwt = include_str!("../../tests/examples/sd_vc.jwt");
        let sd_jwt = VCDM2SdJwt::new_from_compact_sd_jwt(example_sd_jwt.into())?;
        let credential = ParsedCredential::new_sd_jwt(sd_jwt);

        let initiate_api = "http://localhost:3000/api/oid4vp/initiate";

        // Make a request to the OID4VP initiate API.
        // provide a url-encoded `format` parameter to specify the format of the presentation.
        let response: (String, String) = reqwest::Client::new()
            .post(initiate_api)
            .form(&[("format", "sd_jwt")])
            .send()
            .await?
            .json()
            .await?;

        let _id = response.0;
        let url = Url::parse(&response.1).expect("failed to parse url");

        println!("Authorization URL: {url:?}");

        // Make a request to the OID4VP URL.
        let holder = Holder::new_with_credentials(
            vec![credential],
            vec!["did:web:localhost%3A3000:oid4vp:client".into()],
        )
        .await?;

        let permission_request = holder.authorization_request(url).await?;

        let parsed_credentials = permission_request.credentials();

        assert_eq!(parsed_credentials.len(), 1);

        for credential in parsed_credentials.iter() {
            let requested_fields = permission_request.requested_fields(&credential);

            println!("Requested Fields: {requested_fields:?}");

            assert!(requested_fields.len() > 0);
        }

        // NOTE: passing `parsed_credentials` as `selected_credentials`.
        let response = permission_request.create_permission_response(parsed_credentials);

        holder.submit_permission_response(response).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_vehicle_title() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
