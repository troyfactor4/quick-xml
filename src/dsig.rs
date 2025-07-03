//! Minimal support for creating XML Digital Signatures using pure Rust
//! implementations from the RustCrypto project.

use crate::events::Event;
use crate::reader::Reader;
use crate::writer::Writer;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Digest;
use sha2::{Sha256, Sha512};
use std::io::Cursor;
use std::sync::Arc;

/// Supported digest algorithms for XML signatures.
#[derive(Clone, Copy, Debug)]
pub enum DigestMethod {
    /// SHA-256 algorithm
    Sha256,
    /// SHA-512 algorithm
    Sha512,
}

impl Default for DigestMethod {
    fn default() -> Self {
        Self::Sha256
    }
}

impl DigestMethod {
    fn digest_uri(&self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    fn signature_uri(&self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        }
    }
}

#[doc(hidden)]
pub fn canonicalize(xml: &str) -> crate::Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let mut elem = e.into_owned();
                let mut attrs: Vec<(Vec<u8>, Vec<u8>)> = elem
                    .attributes()
                    .map(|a| {
                        let a = a?;
                        Ok((a.key.as_ref().to_vec(), a.value.into_owned()))
                    })
                    .collect::<crate::Result<_>>()?;
                attrs.sort_by(|a, b| a.0.cmp(&b.0));
                elem.clear_attributes();
                for (k, v) in attrs {
                    elem.push_attribute((k.as_slice(), v.as_slice()));
                }
                writer.write_event(Event::Start(elem))?;
            }
            Event::Empty(e) => {
                let mut elem = e.into_owned();
                let mut attrs: Vec<(Vec<u8>, Vec<u8>)> = elem
                    .attributes()
                    .map(|a| {
                        let a = a?;
                        Ok((a.key.as_ref().to_vec(), a.value.into_owned()))
                    })
                    .collect::<crate::Result<_>>()?;
                attrs.sort_by(|a, b| a.0.cmp(&b.0));
                elem.clear_attributes();
                for (k, v) in attrs {
                    elem.push_attribute((k.as_slice(), v.as_slice()));
                }
                writer.write_event(Event::Empty(elem))?;
            }
            Event::End(e) => {
                writer.write_event(Event::End(e))?;
            }
            Event::Text(e) => {
                writer.write_event(Event::Text(e))?;
            }
            Event::CData(e) => {
                writer.write_event(Event::CData(e))?;
            }
            Event::Comment(_) => {
                // skip comments
            }
            Event::Eof => break,
            evt => writer.write_event(evt)?,
        }
        buf.clear();
    }
    let vec = writer.into_inner().into_inner();
    Ok(String::from_utf8(vec).expect("canonicalized xml is valid utf-8"))
}

#[doc(hidden)]
pub fn build_signed_info(method: DigestMethod, digest: &str) -> String {
    format!(
        "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"{}\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"{}\"/><DigestValue>{}</DigestValue></Reference></SignedInfo>",
        method.signature_uri(),
        method.digest_uri(),
        digest
    )
}

#[doc(hidden)]
pub fn sign_data(key: &RsaPrivateKey, data: &[u8], method: DigestMethod) -> Vec<u8> {
    match method {
        DigestMethod::Sha256 => {
            let signing_key = SigningKey::<Sha256>::new(key.clone());
            signing_key.sign(data).to_vec()
        }
        DigestMethod::Sha512 => {
            let signing_key = SigningKey::<Sha512>::new(key.clone());
            signing_key.sign(data).to_vec()
        }
    }
}

#[doc(hidden)]
pub fn digest_data(data: &[u8], method: DigestMethod) -> String {
    match method {
        DigestMethod::Sha256 => STANDARD.encode(Sha256::digest(data)),
        DigestMethod::Sha512 => STANDARD.encode(Sha512::digest(data)),
    }
}

#[doc(hidden)]
pub fn pem_to_base64(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
}

/// Create an XML Digital Signature for the provided document using the given RSA private key.
///
/// The document is canonicalized using a simplified exclusive canonicalization. By default
/// SHA-256 is used as a digest algorithm, but SHA-512 can be selected via [`DigestMethod`].
pub fn sign_document(
    xml: &str,
    pem_key: &str,
    pem_cert: Option<&str>,
    method: Option<DigestMethod>,
) -> crate::Result<String> {
    let method = method.unwrap_or_default();
    let key = RsaPrivateKey::from_pkcs8_pem(pem_key).map_err(|e| {
        crate::Error::Io(Arc::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string(),
        )))
    })?;

    let canon_xml = canonicalize(xml)?;
    let digest_value = digest_data(canon_xml.as_bytes(), method);

    let signed_info = build_signed_info(method, &digest_value);
    let canon_info = canonicalize(&signed_info)?;
    let signature = sign_data(&key, canon_info.as_bytes(), method);
    let signature_value = STANDARD.encode(signature);

    let key_info = pem_cert
        .map(pem_to_base64)
        .map(|cert| format!(
            "<KeyInfo><X509Data><X509Certificate>{cert}</X509Certificate></X509Data></KeyInfo>"
        ))
        .unwrap_or_default();

    Ok(format!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{signed_info}<SignatureValue>{signature_value}</SignatureValue>{key_info}</Signature>",
    ))
}
