//! Minimal DER reader for the parts of an X.509 leaf certificate that the
//! handshake needs: the subject public key and the certificate signature.

use std::io;

use ring::signature;

use crate::crypto::invalid_data;

/// OID 1.3.101.112 (Ed25519).
pub const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// OID 1.2.840.10045.2.1 (id-ecPublicKey).
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// OID 1.2.840.113549.1.1.1 (rsaEncryption).
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Fields of a leaf certificate, borrowed from its DER encoding.
#[derive(Debug, Clone, Copy)]
pub struct LeafCertificate<'a> {
    /// Algorithm OID of the subjectPublicKeyInfo (content octets only).
    pub public_key_algorithm: &'a [u8],
    /// subjectPublicKey BIT STRING content without the unused-bits octet.
    pub public_key: &'a [u8],
    /// signatureValue BIT STRING content without the unused-bits octet.
    pub signature: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first_len = *input.get(1)?;
    let (len, header) = if first_len < 0x80 {
        (first_len as usize, 2)
    } else {
        let octets = (first_len & 0x7f) as usize;
        if octets == 0 || octets > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..octets {
            len = (len << 8) | *input.get(2 + i)? as usize;
        }
        (len, 2 + octets)
    };
    let end = header.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((tag, &input[header..end], &input[end..]))
}

fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, content, rest) = read_tlv(input)?;
    (found == tag).then_some((content, rest))
}

fn bit_string(content: &[u8]) -> Option<&[u8]> {
    match content.split_first() {
        Some((0, bits)) => Some(bits),
        _ => None,
    }
}

/// Parses the leaf certificate fields; returns `None` for malformed input.
pub fn parse_leaf(der: &[u8]) -> Option<LeafCertificate<'_>> {
    let (certificate, _) = expect(der, 0x30)?;
    let (tbs, rest) = expect(certificate, 0x30)?;
    let (_signature_algorithm, rest) = expect(rest, 0x30)?;
    let (signature_bits, _) = expect(rest, 0x03)?;
    let signature = bit_string(signature_bits)?;

    let mut fields = tbs;
    if fields.first() == Some(&0xa0) {
        fields = read_tlv(fields)?.2;
    }
    let (_serial, fields) = expect(fields, 0x02)?;
    let (_tbs_signature, fields) = expect(fields, 0x30)?;
    let (_issuer, fields) = expect(fields, 0x30)?;
    let (_validity, fields) = expect(fields, 0x30)?;
    let (_subject, fields) = expect(fields, 0x30)?;
    let (spki, _) = expect(fields, 0x30)?;
    let (algorithm, spki_rest) = expect(spki, 0x30)?;
    let (algorithm_oid, _) = expect(algorithm, 0x06)?;
    let (key_bits, _) = expect(spki_rest, 0x03)?;
    Some(LeafCertificate {
        public_key_algorithm: algorithm_oid,
        public_key: bit_string(key_bits)?,
        signature,
    })
}

/// Verifies a TLS 1.3 CertificateVerify signature made with the leaf key.
pub fn verify_signature(
    scheme: u16,
    leaf: &LeafCertificate<'_>,
    message: &[u8],
    signature_bytes: &[u8],
) -> io::Result<()> {
    let algorithm: &'static dyn signature::VerificationAlgorithm = match scheme {
        0x0807 if leaf.public_key_algorithm == OID_ED25519 => &signature::ED25519,
        0x0403 if leaf.public_key_algorithm == OID_EC_PUBLIC_KEY => {
            &signature::ECDSA_P256_SHA256_ASN1
        }
        0x0503 if leaf.public_key_algorithm == OID_EC_PUBLIC_KEY => {
            &signature::ECDSA_P384_SHA384_ASN1
        }
        0x0804 if leaf.public_key_algorithm == OID_RSA_ENCRYPTION => {
            &signature::RSA_PSS_2048_8192_SHA256
        }
        0x0805 if leaf.public_key_algorithm == OID_RSA_ENCRYPTION => {
            &signature::RSA_PSS_2048_8192_SHA384
        }
        0x0806 if leaf.public_key_algorithm == OID_RSA_ENCRYPTION => {
            &signature::RSA_PSS_2048_8192_SHA512
        }
        _ => return Err(invalid_data("unsupported TLS CertificateVerify scheme")),
    };
    signature::UnparsedPublicKey::new(algorithm, leaf.public_key)
        .verify(message, signature_bytes)
        .map_err(|_| invalid_data("TLS CertificateVerify signature is invalid"))
}
