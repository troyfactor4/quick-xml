use base64::{engine::general_purpose::STANDARD, Engine as _};
use pretty_assertions::assert_eq;
use quick_xml::dsig::{
    build_signed_info, canonicalize, digest_data, pem_to_base64, sign_data, sign_document,
    DigestMethod,
};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC5pY2ByUWhTkc6\nfgDqQHNTFuq6gWYtft7SgMStPURR7cQVTjcjzs9aMdoMQ53fQszRYBQf4zKkADnv\ne+ADMeXSfXVotygX4dPYmWSLXfrp1i1PNkBViNVzesSihXr8A+4WXzx5InsWuHTm\nBTaYJMk04RfbZM7CTzJHmVZeVDlc1LDB1DhTrrvZ70Rr/dr1HJAEzGMzeJB1fffn\nQDK0mrMhEmmumvAWefq6QSW7OTrV4VpMHzoFPomnfj7Q2PZ3QEv6u8RnYm5KvC/p\nsCRgc8XGf6i05pEBlYgoMOu28gToAonZuXbJwraylRGQt8CxxIhu2gGtgpVTGxo4\nfyQxU4EbAgMBAAECggEAHorMExQn7nfQZCEiyWc9EehtSa3MP6PlyMACm3W+7bOu\nVMr/a1a06mPVObtOF9MHm1KxPOXGCRE4dtvsaNoms1CMpmOrpvIyRipGTl9xzlK8\nNZH5V5khdNQ30X0gVKHY47lbW5p+oahLIySsbK9wotB9ekzFb1ZUMU9a1D4LCehz\nrgff084CTU6RNTE1oX1hoQ1abBJaM1CjKzg8Yhw/IvPUX5R6cOUwXVbkDJQix8T6\ntN8m2QM1JtPtqJNgc77NAQ56ZFfCkuQzL7v7KUv1Lai7iLUbOHMT0enDMXzPNbiC\nuLMMV77WzuC8o+N6Czmqku3SOuPbZtMbuzcj/6onoQKBgQD4MMoTRTU6tVWmG7B3\ncuxoLV7t9KtpDWDWXqSOIKRiz1YZnXELIsaeO97pvEj7K3f2qdjSXxwEFOdyvIg0\nC3DObsAtYekPVM+rJSUE7532XVgqbrwv7hNdsePqxO8XStlHappVLU7KRwE7LTZs\n7iUwPZxKsj3ocYqng+6f/wctEwKBgQC/fPahkusjIsZi0ZkoXwYmpODpB/vHfePl\n8P9fwwGiKFoUP32EhYpl4iuv1AGYtIgyWKyaRAa8/RNj7ev39ZY0LvgKobOFK/4i\nYI55HM4PAR0ElFAuIjjjQZnDX4PuvbIzQdMs8Qu5kaABZYtZNVwPkj8oyjZsJAiH\nQmLaXY4E2QKBgHEhRCsug8nj+EuEGZcJEouWCsxql2uGRprQfy+t32CO488/PdT2\noBRmdACU66tZsBAGcafK5KlTogBhwa//ewcN4pmNJL/xR8vaXZp3Ysh22gZVfYBX\nhApUWPCdneI/IvVzuS+UPHLllMEVpdZXYyovGzvNLXzzrGEZOT9C71FzAoGAEmVW\n7D7JCB8XH/cy14YJeTztvnVd4tRdSIHWhsSdK47k2H0g+dI6cX9A4yti2+C8FNof\n+tH+M7m8WyVIPhIB1BGPErZmIK0RRQwxo8D4qshYmVAGQ+hVvr9WnkZWzmC69eGk\n//RIRBORY5D1yiQuK/DI0IpcoBb2Gsht5ryGIEECgYApyJMiwhm8LUlTbjigcyBq\nJT7xSJzgnxyTS5FjjjPp8I2M+hgKvawn4XCggVhNXkos+DJ6mKymP8tD+7GB/5P+\ngZoFrjSa5yd1eibQklpYm9d0M1AmVgVg/bMEcW19TWvyyFE26vHFl9+F8XGu1AwH\npHRvsFqEnlA9ztMwCkD40Q==\n-----END PRIVATE KEY-----\n";
const TEST_CERT: &str = include_str!("data/test-cert.pem");

#[test]
fn sign_document_sha256() {
    let xml = "<root><data>test</data></root>";
    let actual = sign_document(xml, TEST_KEY, Some(TEST_CERT), None).unwrap();

    let method = DigestMethod::Sha256;
    let key = RsaPrivateKey::from_pkcs8_pem(TEST_KEY).unwrap();
    let canon_xml = canonicalize(xml).unwrap();
    let digest_value = digest_data(canon_xml.as_bytes(), method);
    let signed_info = build_signed_info(method, &digest_value);
    let canon_info = canonicalize(&signed_info).unwrap();
    let signature = sign_data(&key, canon_info.as_bytes(), method);
    let signature_value = STANDARD.encode(signature);
    let key_info = format!("<KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo>", pem_to_base64(TEST_CERT));
    let expected = format!(r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{signed_info}<SignatureValue>{signature_value}</SignatureValue>{key_info}</Signature>"#);

    assert_eq!(actual, expected);
}

#[test]
fn sign_document_sha512() {
    let xml = "<root><data>test</data></root>";
    let actual = sign_document(xml, TEST_KEY, Some(TEST_CERT), Some(DigestMethod::Sha512)).unwrap();

    let method = DigestMethod::Sha512;
    let key = RsaPrivateKey::from_pkcs8_pem(TEST_KEY).unwrap();
    let canon_xml = canonicalize(xml).unwrap();
    let digest_value = digest_data(canon_xml.as_bytes(), method);
    let signed_info = build_signed_info(method, &digest_value);
    let canon_info = canonicalize(&signed_info).unwrap();
    let signature = sign_data(&key, canon_info.as_bytes(), method);
    let signature_value = STANDARD.encode(signature);
    let key_info = format!("<KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo>", pem_to_base64(TEST_CERT));
    let expected = format!(r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{signed_info}<SignatureValue>{signature_value}</SignatureValue>{key_info}</Signature>"#);

    assert_eq!(actual, expected);
}

#[test]
fn sign_document_invalid_key() {
    let xml = "<root/>";
    let bad_key = "-----BEGIN PRIVATE KEY-----\nMII...bad\n-----END PRIVATE KEY-----";
    let result = sign_document(xml, bad_key, Some(TEST_CERT), None);
    assert!(result.is_err());
}

#[test]
fn sign_document_invalid_xml() {
    let xml = "<root><"; // malformed
    let result = sign_document(xml, TEST_KEY, Some(TEST_CERT), None);
    assert!(result.is_err());
}
