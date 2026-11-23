//! The server's own certificate authority and TLS settings.
//!
//! On first start the server makes its own certificate authority (EC P-256,
//! 20 years, path length 0) and a server certificate (10 years) for the names
//! devices use to reach it. Devices pin the authority by its fingerprint
//! (base64url SHA-256 of its DER), exactly as with the Docker server in the
//! vault repo, so a join link made by either works the same.
//!
//! Key exchange prefers the hybrid X25519MLKEM768 (X25519 plus ML-KEM-768),
//! so recorded traffic stays safe against a future quantum computer. Clients
//! that only know X25519 or P-256 still connect.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::files;
use crate::util::fingerprint;

/// The certificate names for a list of hosts: always `localhost` and
/// `127.0.0.1`, then every name or address given, without duplicates.
pub fn names(hosts: &[String]) -> Vec<String> {
    let mut out = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    for h in hosts {
        let h = h.trim();
        if !h.is_empty() && !out.iter().any(|x| x == h) {
            out.push(h.to_owned());
        }
    }
    out
}

/// Splits "a, b,c" into hosts.
pub fn parse_hosts(s: &str) -> Vec<String> {
    s.split(',')
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect()
}

fn validity(params: &mut CertificateParams, years: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * years);
}

/// Makes the certificate authority in `dir` if it is not there yet.
/// Returns true when it made a new one.
pub fn ensure_ca(dir: &Path) -> Result<bool> {
    let (pem, key) = (dir.join("ca.pem"), dir.join("ca.key"));
    if pem.exists() && key.exists() {
        return Ok(false);
    }
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Secret Vault sync server (own CA)");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut p, 20);
    let cert = p.self_signed(&kp)?;
    files::write_private(&key, kp.serialize_pem().as_bytes())?;
    files::write_private(&pem, cert.pem().as_bytes())?;
    // A new authority makes any old server certificate useless.
    let _ = std::fs::remove_file(dir.join("server.crt"));
    Ok(true)
}

/// Makes the server certificate again when the names changed (the authority
/// stays, so devices that joined keep trusting the server). Returns true when
/// it made a new one.
pub fn ensure_server_cert(dir: &Path, names: &[String]) -> Result<bool> {
    let crt = dir.join("server.crt");
    let wanted = names.join(",");
    let had = std::fs::read_to_string(dir.join("hosts")).unwrap_or_default();
    if crt.exists() && dir.join("server.key").exists() && had == wanted {
        return Ok(false);
    }
    let ca_pem = std::fs::read_to_string(dir.join("ca.pem"))?;
    let ca_key = KeyPair::from_pem(&std::fs::read_to_string(dir.join("ca.key"))?)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key)
        .context("reading this server's certificate authority")?;
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut p = CertificateParams::new(names.to_vec())?;
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        names.get(2).or(names.first()).cloned().unwrap_or_default(),
    );
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    validity(&mut p, 10);
    let cert = p.signed_by(&kp, &issuer)?;
    files::write_private(&dir.join("server.key"), kp.serialize_pem().as_bytes())?;
    files::write_private(&crt, cert.pem().as_bytes())?;
    files::write_private(&dir.join("hosts"), wanted.as_bytes())?;
    Ok(true)
}

/// The authority's fingerprint, as join links carry it.
pub fn ca_fingerprint(dir: &Path) -> Result<String> {
    let der = CertificateDer::from_pem_file(dir.join("ca.pem"))
        .context("reading this server's certificate authority")?;
    Ok(fingerprint(der.as_ref()))
}

/// The crypto this server uses: aws-lc-rs, key exchange in this order.
pub fn provider() -> CryptoProvider {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
    ];
    p
}

/// TLS 1.3 only: every Secret Vault client uses rustls, which has it.
pub fn server_config(dir: &Path) -> Result<Arc<ServerConfig>> {
    let mut chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(dir.join("server.crt"))?.collect::<Result<_, _>>()?;
    chain.push(CertificateDer::from_pem_file(dir.join("ca.pem"))?);
    let key = PrivateKeyDer::from_pem_file(dir.join("server.key"))?;
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if cfg.crypto_provider().kx_groups.first().map(|g| g.name())
        != Some(rustls::NamedGroup::X25519MLKEM768)
    {
        bail!("post-quantum key exchange is not available in this build");
    }
    Ok(Arc::new(cfg))
}
