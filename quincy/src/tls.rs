//! Host-owned TLS identity and public client trust, independent of persistence.

use std::collections::HashSet;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};

use crate::certificates::compute_cert_fingerprint;
use crate::error::{ConfigError, Result};

#[cfg(test)]
mod tests;

/// One server identity and an explicit set of public client CA roots.
/// No CA signing key is accepted. User fingerprints remain a separate grant.
#[derive(Clone, Debug)]
pub struct Identity {
    pub(crate) key: Arc<CertifiedKey>,
    roots: Arc<RootCertStore>,
}

impl Identity {
    pub fn new(key: Arc<CertifiedKey>, roots: &[CertificateDer<'static>]) -> Result<Self> {
        key.keys_match()?;
        let mut store = RootCertStore::empty();
        for root in roots {
            store.add(root.clone())?;
        }
        if store.is_empty() {
            return Err(ConfigError::MissingField {
                field: "client CA roots".into(),
            }
            .into());
        }
        Ok(Self {
            key,
            roots: Arc::new(store),
        })
    }

    pub(crate) fn verifier(
        &self,
        provider: Arc<CryptoProvider>,
        allowed: HashSet<String>,
    ) -> Result<Arc<dyn ClientCertVerifier>> {
        let chain = WebPkiClientVerifier::builder_with_provider(self.roots.clone(), provider)
            .build()
            .map_err(|error| ConfigError::InvalidValue {
                field: "client CA roots".into(),
                reason: error.to_string(),
            })?;
        Ok(Arc::new(Verifier { chain, allowed }))
    }
}

#[derive(Debug)]
struct Verifier {
    chain: Arc<dyn ClientCertVerifier>,
    allowed: HashSet<String>,
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chain.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, Error> {
        if !self.allowed.contains(&compute_cert_fingerprint(leaf)) {
            return Err(Error::General(
                "client certificate is not authorized".into(),
            ));
        }
        self.chain.verify_client_cert(leaf, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.chain.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.chain.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}
