#[cfg(test)]
mod tests {
    use ssi::{
        json_ld::ContextLoader,
        prelude::AnyJsonCredential,
    };
    use ssi_rdf::{LdEnvironment, IntoNQuads, urdna2015};
    use ssi_json_ld::Expandable;
    use sha2::{Digest, Sha256};

    const CREDENTIAL_NO_PROOF: &str = r#"{"@context":["https://www.w3.org/ns/credentials/v2",{"BenTestSchema":"https://w3id.org/aq/credential/v1/BenTestSchema","first":"https://w3id.org/aq/credential/v1/first"}],"id":"urn:uuid:87f99576-2d5a-4775-b3f9-6a5852a68baf","type":["VerifiableCredential","BenTestSchema"],"issuer":"did:web:0identitycredential-crew.dids.aqvc.me","validFrom":"2026-06-30T15:45:01.120Z","validUntil":"2027-06-30T15:45:01.120Z","credentialSubject":{"id":"did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjEyYnE4aDUtVENHVnNfcmhHM2tRb09QWkxLZHRhWGt1UzNvQ2F1U0JJS2MiLCJ5Ijoic0c3akdLbkFFcDdoV3Z4ZzYyczhjSmhKdEVMQl9OeGRwVzZXVDNCbTFGWSJ9","first":"veniam fugiat cu"}}"#;

    #[tokio::test]
    async fn print_credential_nquads() {
        let loader = ContextLoader::empty().with_static_loader();
        let credential: AnyJsonCredential = serde_json::from_str(CREDENTIAL_NO_PROOF)
            .expect("parse credential");

        let mut ld = LdEnvironment::default();
        let mut expanded = credential
            .expand_with(&mut ld, &loader)
            .await
            .expect("expand");
        expanded.canonicalize();

        let quads = linked_data::to_lexical_quads_with(
            &mut ld.vocabulary,
            &mut ld.interpretation,
            &expanded,
        ).expect("to_quads");

        let nquads_lines: Vec<String> = urdna2015::normalize(quads.into_iter()).into_nquads_lines();

        println!("\n=== CREDENTIAL BODY N-QUADS ({} total) ===", nquads_lines.len());
        for (i, line) in nquads_lines.iter().enumerate() {
            println!("[{}] {}", i, line);
        }

        // mandatory indices are [1,2,3,4,5,6]
        let mandatory: Vec<&str> = [1,2,3,4,5,6].iter()
            .map(|&i| nquads_lines[i].as_str())
            .collect();
        let mandatory_hash = Sha256::digest(mandatory.join("").as_bytes());
        println!("\n=== MANDATORY HASH (indices 1-6) ===");
        println!("SHA256: {:x}", mandatory_hash);
    }
}
