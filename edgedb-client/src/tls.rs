use std::sync::Arc;

use async_tls::TlsConnector;
use rustls::{ClientConfig, ServerCertVerifier, ServerCertVerified, TLSError, RootCertStore,
             Certificate, OwnedTrustAnchor};
use webpki;
use webpki_roots;
use async_std::net::TcpStream;
use async_tls::client::TlsStream;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'b>>,
);

fn prepare<'a, 'b>(
    roots: &'b RootCertStore,
    presented_certs: &'a [Certificate],
) -> Result<CertChainAndRoots<'a, 'b>, TLSError> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert = webpki::EndEntityCert::from(&presented_certs[0].0).map_err(TLSError::WebPKIError)?;

    let chain: Vec<&'a [u8]> = presented_certs
        .iter()
        .skip(1)
        .map(|cert| cert.0.as_ref())
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots
        .roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect();

    Ok((cert, chain, trustroots))
}

fn try_now() -> Result<webpki::Time, TLSError> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
}

pub type CertificateCallback = fn(&[Certificate], &mut RootCertStore) -> bool;

pub struct ServerCertificates {
    callback: Option<CertificateCallback>,
}

impl ServerCertificates {
    pub fn new(callback: Option<CertificateCallback>) -> Self {
        ServerCertificates {
            callback,
        }
    }
}

impl ServerCertVerifier for ServerCertificates {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: webpki::DNSNameRef,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(roots, presented_certs)?;
        let now = try_now()?;
        if let Err(mut e) = cert.verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSServerTrustAnchors(&trustroots),
            &chain,
            now,
        ) {
            if let Some(callback) = self.callback {
                loop {
                    let mut new_roots = RootCertStore::empty();
                    for root in &roots.roots {
                        new_roots.roots.push(root.clone());
                    }
                    if callback(presented_certs, &mut new_roots) {
                        let (cert, chain, trustroots) = prepare(&new_roots, presented_certs)?;
                        let now = try_now()?;
                        match cert.verify_is_valid_tls_server_cert(
                            SUPPORTED_SIG_ALGS,
                            &webpki::TLSServerTrustAnchors(&trustroots),
                            &chain,
                            now,
                        ) {
                            Ok(_) => {
                                return Ok(ServerCertVerified::assertion());
                            },
                            Err(ne) => {
                                e = ne;
                            },
                        }
                    } else {
                        break;
                    }
                }
            }
            return Err(TLSError::WebPKIError(e));
        }

        // Hostname check is intentionally skipped here
        Ok(ServerCertVerified::assertion())
    }
}

pub async fn connect_tls(host: &String, port: &u16, callback: Option<CertificateCallback>)
    -> anyhow::Result<TlsStream<TcpStream>>
{
    let conn = TcpStream::connect(&(&host[..], *port)).await?;
    let certs = Arc::new(ServerCertificates::new(callback));
    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.dangerous().set_certificate_verifier(certs);
    let connector = TlsConnector::from(config);
    Ok(connector.connect(host, conn).await?)
}
