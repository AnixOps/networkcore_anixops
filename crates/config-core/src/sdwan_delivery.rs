use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use control_domain::{DomainError, DomainResult};
use ring::{digest, signature};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::IpAddr;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

pub const SDWAN_DELIVERY_SCHEMA_V1: &str = "anixops.sdwan.delivery/v1";
pub const SDWAN_DELIVERY_SIGNATURE_DOMAIN_V1: &str = "anixops.sdwan.delivery-signature/v1";
pub const SDWAN_DELIVERY_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const SDWAN_DELIVERY_PARSE_FAILED_CODE: &str = "sdwan.delivery.parse_failed";
pub const SDWAN_DELIVERY_PUBLIC_KEY_INVALID_CODE: &str = "sdwan.delivery.public_key_invalid";
pub const SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE: &str = "sdwan.delivery.payload_hash_invalid";
pub const SDWAN_DELIVERY_SIGNATURE_INVALID_CODE: &str = "sdwan.delivery.signature_invalid";
pub const SDWAN_DELIVERY_EXPIRED_CODE: &str = "sdwan.delivery.expired";

#[derive(Debug, Clone)]
pub struct SdwanDeliveryVerifier {
    public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeliveryEnvelope {
    pub bundle_kind: String,
    pub bundle_id: String,
    pub tenant_id: String,
    pub target_id: String,
    pub sequence: u64,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub key_id: String,
    pub payload: Vec<u8>,
    pub profile: DeliveryProfile,
    pub signing_input_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryProfile {
    Client(ClientDeliveryProfile),
    Pop(PopDeliveryProfile),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDeliveryProfile {
    pub id: String,
    pub principal_id: String,
    pub transport: String,
    pub pops: Vec<DeliveryPopReference>,
    pub mitm: Option<DeliveryMitmProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPopReference {
    pub id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryMitmProfile {
    pub allowed_domain_suffixes: Vec<String>,
    pub require_consent: bool,
    pub block_quic: bool,
    pub block_pinned_tls: bool,
    pub metadata_retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopDeliveryProfile {
    pub id: String,
    pub principal_id: String,
    pub routes: Vec<DeliveryRoutePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRoutePolicy {
    pub id: String,
    pub selector: DeliveryRouteSelector,
    pub chain: DeliveryServiceChain,
    pub direct_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRouteSelector {
    pub source_cidr: Option<String>,
    pub destination_cidr: Option<String>,
    pub protocol: Option<String>,
    pub ports: Option<DeliveryPortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryServiceChain {
    pub id: String,
    pub hops: Vec<String>,
    pub return_hops: Option<Vec<String>>,
}

impl SdwanDeliveryVerifier {
    pub fn new(public_key: &[u8]) -> DomainResult<Self> {
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| public_key_error())?;

        Ok(Self { public_key })
    }

    pub fn verify_json(
        &self,
        input: &[u8],
        now: OffsetDateTime,
    ) -> DomainResult<VerifiedDeliveryEnvelope> {
        let envelope: SignedEnvelopeWire =
            serde_json::from_slice(input).map_err(|_| envelope_parse_error())?;
        let metadata = validate_envelope_metadata(&envelope, now)?;

        let payload =
            decode_standard_base64(&envelope.payload_base64).map_err(|_| payload_hash_error())?;
        let payload_digest = digest::digest(&digest::SHA256, &payload);
        if lowercase_hex(payload_digest.as_ref()) != envelope.payload_sha256 {
            return Err(payload_hash_error());
        }

        let signing_input = build_signing_input(&envelope, payload_digest.as_ref())?;
        let signature_bytes =
            decode_standard_base64(&envelope.signature).map_err(|_| signature_error())?;
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, self.public_key.as_slice());
        public_key
            .verify(&signing_input, &signature_bytes)
            .map_err(|_| signature_error())?;

        let profile = parse_delivery_profile(&payload, envelope.bundle_kind, &metadata.target_id)?;

        Ok(VerifiedDeliveryEnvelope {
            bundle_kind: envelope.bundle_kind.as_str().to_string(),
            bundle_id: metadata.bundle_id,
            tenant_id: metadata.tenant_id,
            target_id: metadata.target_id,
            sequence: envelope.sequence,
            issued_at: metadata.issued_at,
            expires_at: metadata.expires_at,
            key_id: metadata.key_id,
            payload,
            profile,
            signing_input_hex: lowercase_hex(&signing_input),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelopeWire {
    schema_version: String,
    bundle_kind: DeliveryBundleKindWire,
    bundle_id: String,
    tenant_id: String,
    target_id: String,
    sequence: u64,
    issued_at: String,
    expires_at: String,
    key_id: String,
    payload_base64: String,
    algorithm: DeliverySignatureAlgorithmWire,
    payload_sha256: String,
    signature: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DeliveryBundleKindWire {
    Client,
    Pop,
}

impl DeliveryBundleKindWire {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Pop => "pop",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DeliverySignatureAlgorithmWire {
    Ed25519,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPayloadWire {
    schema_version: String,
    kind: DeliveryBundleKindWire,
    client: Option<ClientDeliveryProfileWire>,
    pop: Option<PopDeliveryProfileWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientDeliveryProfileWire {
    id: String,
    principal_id: String,
    transport: String,
    pops: Vec<DeliveryPopReferenceWire>,
    mitm: Option<DeliveryMitmProfileWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPopReferenceWire {
    id: String,
    endpoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryMitmProfileWire {
    allowed_domain_suffixes: Vec<String>,
    require_consent: bool,
    block_quic: bool,
    block_pinned_tls: bool,
    metadata_retention_days: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PopDeliveryProfileWire {
    id: String,
    principal_id: String,
    routes: Vec<DeliveryRoutePolicyWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryRoutePolicyWire {
    id: String,
    selector: DeliveryRouteSelectorWire,
    chain: DeliveryServiceChainWire,
    #[serde(default)]
    direct_fallback: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryRouteSelectorWire {
    source_cidr: Option<String>,
    destination_cidr: Option<String>,
    protocol: Option<String>,
    ports: Option<DeliveryPortRangeWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryPortRangeWire {
    start: i64,
    end: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryServiceChainWire {
    id: String,
    hops: Vec<String>,
    return_hops: Option<Vec<String>>,
}

#[derive(Debug)]
struct EnvelopeMetadata {
    bundle_id: String,
    tenant_id: String,
    target_id: String,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    key_id: String,
}

fn validate_envelope_metadata(
    envelope: &SignedEnvelopeWire,
    now: OffsetDateTime,
) -> DomainResult<EnvelopeMetadata> {
    if envelope.schema_version != SDWAN_DELIVERY_SCHEMA_V1
        || envelope.sequence == 0
        || !matches!(envelope.algorithm, DeliverySignatureAlgorithmWire::Ed25519)
    {
        return Err(envelope_parse_error());
    }

    let bundle_id = required_envelope_identifier(&envelope.bundle_id)?;
    let tenant_id = required_envelope_identifier(&envelope.tenant_id)?;
    let target_id = required_envelope_identifier(&envelope.target_id)?;
    let key_id = required_envelope_identifier(&envelope.key_id)?;
    let issued_at = parse_wire_timestamp(&envelope.issued_at)?;
    let expires_at = parse_wire_timestamp(&envelope.expires_at)?;

    if expires_at <= issued_at {
        return Err(envelope_parse_error());
    }
    if expires_at <= now {
        return Err(expired_error());
    }

    Ok(EnvelopeMetadata {
        bundle_id,
        tenant_id,
        target_id,
        issued_at,
        expires_at,
        key_id,
    })
}

fn parse_wire_timestamp(value: &str) -> DomainResult<OffsetDateTime> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| envelope_parse_error())?;
    if timestamp.offset() != UtcOffset::UTC {
        return Err(envelope_parse_error());
    }

    Ok(timestamp)
}

fn build_signing_input(
    envelope: &SignedEnvelopeWire,
    payload_digest: &[u8],
) -> DomainResult<Vec<u8>> {
    let sequence = envelope.sequence.to_string();
    let mut signing_input = Vec::new();

    append_signing_field(
        &mut signing_input,
        SDWAN_DELIVERY_SIGNATURE_DOMAIN_V1.as_bytes(),
    )?;
    append_signing_field(&mut signing_input, envelope.schema_version.as_bytes())?;
    append_signing_field(&mut signing_input, envelope.bundle_kind.as_str().as_bytes())?;
    append_signing_field(&mut signing_input, envelope.bundle_id.as_bytes())?;
    append_signing_field(&mut signing_input, envelope.tenant_id.as_bytes())?;
    append_signing_field(&mut signing_input, envelope.target_id.as_bytes())?;
    append_signing_field(&mut signing_input, sequence.as_bytes())?;
    append_signing_field(&mut signing_input, envelope.issued_at.as_bytes())?;
    append_signing_field(&mut signing_input, envelope.expires_at.as_bytes())?;
    append_signing_field(&mut signing_input, envelope.key_id.as_bytes())?;
    append_signing_field(&mut signing_input, payload_digest)?;

    Ok(signing_input)
}

fn append_signing_field(output: &mut Vec<u8>, field: &[u8]) -> DomainResult<()> {
    let field_length = u32::try_from(field.len()).map_err(|_| envelope_parse_error())?;
    output.extend_from_slice(&field_length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

fn parse_delivery_profile(
    payload: &[u8],
    bundle_kind: DeliveryBundleKindWire,
    target_id: &str,
) -> DomainResult<DeliveryProfile> {
    let payload: DeliveryPayloadWire =
        serde_json::from_slice(payload).map_err(|_| profile_parse_error())?;

    if payload.schema_version != SDWAN_DELIVERY_SCHEMA_V1 || payload.kind != bundle_kind {
        return Err(profile_parse_error());
    }

    match (bundle_kind, payload.client, payload.pop) {
        (DeliveryBundleKindWire::Client, Some(client), None) => {
            validate_client_profile(client, target_id).map(DeliveryProfile::Client)
        }
        (DeliveryBundleKindWire::Pop, None, Some(pop)) => {
            validate_pop_profile(pop, target_id).map(DeliveryProfile::Pop)
        }
        _ => Err(profile_parse_error()),
    }
}

fn validate_client_profile(
    profile: ClientDeliveryProfileWire,
    target_id: &str,
) -> DomainResult<ClientDeliveryProfile> {
    let ClientDeliveryProfileWire {
        id,
        principal_id,
        transport,
        pops,
        mitm,
    } = profile;
    let id = required_profile_text(&id)?;
    let principal_id = required_profile_text(&principal_id)?;

    if id != target_id || transport != "ikev2" || pops.is_empty() {
        return Err(profile_parse_error());
    }

    let pops = pops
        .into_iter()
        .map(validate_pop_reference)
        .collect::<DomainResult<Vec<_>>>()?;
    let mitm = mitm.map(validate_mitm_profile).transpose()?;

    Ok(ClientDeliveryProfile {
        id,
        principal_id,
        transport,
        pops,
        mitm,
    })
}

fn validate_pop_reference(
    reference: DeliveryPopReferenceWire,
) -> DomainResult<DeliveryPopReference> {
    Ok(DeliveryPopReference {
        id: required_profile_text(&reference.id)?,
        endpoint: validate_endpoint(&reference.endpoint)?,
    })
}

fn validate_mitm_profile(profile: DeliveryMitmProfileWire) -> DomainResult<DeliveryMitmProfile> {
    if profile.allowed_domain_suffixes.is_empty()
        || !profile.require_consent
        || !profile.block_quic
        || !profile.block_pinned_tls
        || profile.metadata_retention_days != 7
    {
        return Err(profile_parse_error());
    }

    let allowed_domain_suffixes = profile
        .allowed_domain_suffixes
        .into_iter()
        .map(|suffix| validate_dns_suffix(&suffix))
        .collect::<DomainResult<Vec<_>>>()?;

    Ok(DeliveryMitmProfile {
        allowed_domain_suffixes,
        require_consent: profile.require_consent,
        block_quic: profile.block_quic,
        block_pinned_tls: profile.block_pinned_tls,
        metadata_retention_days: 7,
    })
}

fn validate_pop_profile(
    profile: PopDeliveryProfileWire,
    target_id: &str,
) -> DomainResult<PopDeliveryProfile> {
    let PopDeliveryProfileWire {
        id,
        principal_id,
        routes,
    } = profile;
    let id = required_profile_text(&id)?;
    let principal_id = required_profile_text(&principal_id)?;

    if id != target_id || routes.is_empty() {
        return Err(profile_parse_error());
    }

    let routes = routes
        .into_iter()
        .map(validate_route_policy)
        .collect::<DomainResult<Vec<_>>>()?;

    Ok(PopDeliveryProfile {
        id,
        principal_id,
        routes,
    })
}

fn validate_route_policy(route: DeliveryRoutePolicyWire) -> DomainResult<DeliveryRoutePolicy> {
    if route.direct_fallback {
        return Err(profile_parse_error());
    }

    Ok(DeliveryRoutePolicy {
        id: required_profile_text(&route.id)?,
        selector: validate_route_selector(route.selector)?,
        chain: validate_service_chain(route.chain)?,
        direct_fallback: false,
    })
}

fn validate_route_selector(
    selector: DeliveryRouteSelectorWire,
) -> DomainResult<DeliveryRouteSelector> {
    if selector.source_cidr.is_none()
        && selector.destination_cidr.is_none()
        && selector.protocol.is_none()
        && selector.ports.is_none()
    {
        return Err(profile_parse_error());
    }

    let source_cidr = selector
        .source_cidr
        .map(|cidr| validate_cidr(&cidr))
        .transpose()?;
    let destination_cidr = selector
        .destination_cidr
        .map(|cidr| validate_cidr(&cidr))
        .transpose()?;
    let protocol = selector
        .protocol
        .map(|protocol| validate_protocol(&protocol))
        .transpose()?;
    let ports = match selector.ports {
        Some(ports) if protocol.is_some() => Some(validate_port_range(ports)?),
        Some(_) => return Err(profile_parse_error()),
        None => None,
    };

    Ok(DeliveryRouteSelector {
        source_cidr,
        destination_cidr,
        protocol,
        ports,
    })
}

fn validate_cidr(value: &str) -> DomainResult<String> {
    let cidr = required_profile_text(value)?;
    let (address, prefix) = cidr.split_once('/').ok_or_else(profile_parse_error)?;
    let address: IpAddr = address.parse().map_err(|_| profile_parse_error())?;
    let prefix: u8 = prefix.parse().map_err(|_| profile_parse_error())?;
    let maximum_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > maximum_prefix {
        return Err(profile_parse_error());
    }

    Ok(cidr)
}

fn validate_protocol(value: &str) -> DomainResult<String> {
    match value {
        "tcp" | "udp" => Ok(value.to_string()),
        _ => Err(profile_parse_error()),
    }
}

fn validate_port_range(range: DeliveryPortRangeWire) -> DomainResult<DeliveryPortRange> {
    if !(1..=65_535).contains(&range.start)
        || !(1..=65_535).contains(&range.end)
        || range.start > range.end
    {
        return Err(profile_parse_error());
    }

    Ok(DeliveryPortRange {
        start: range.start as u16,
        end: range.end as u16,
    })
}

fn validate_service_chain(chain: DeliveryServiceChainWire) -> DomainResult<DeliveryServiceChain> {
    if chain.hops.is_empty() {
        return Err(profile_parse_error());
    }

    Ok(DeliveryServiceChain {
        id: required_profile_text(&chain.id)?,
        hops: validate_unique_hops(chain.hops)?,
        return_hops: chain.return_hops.map(validate_unique_hops).transpose()?,
    })
}

fn validate_unique_hops(hops: Vec<String>) -> DomainResult<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(hops.len());

    for hop in hops {
        let hop = required_profile_text(&hop)?;
        if !seen.insert(hop.clone()) {
            return Err(profile_parse_error());
        }
        validated.push(hop);
    }

    Ok(validated)
}

fn validate_endpoint(value: &str) -> DomainResult<String> {
    let endpoint = required_profile_text(value)?;
    let (host, port) = if let Some(value) = endpoint.strip_prefix('[') {
        value.split_once("]:").ok_or_else(profile_parse_error)?
    } else {
        endpoint.rsplit_once(':').ok_or_else(profile_parse_error)?
    };

    if host.is_empty()
        || host.trim() != host
        || host.contains('[')
        || host.contains(']')
        || (!endpoint.starts_with('[') && host.contains(':'))
    {
        return Err(profile_parse_error());
    }

    let port: u16 = port.parse().map_err(|_| profile_parse_error())?;
    if port == 0 {
        return Err(profile_parse_error());
    }

    Ok(endpoint)
}

fn validate_dns_suffix(value: &str) -> DomainResult<String> {
    let suffix = required_profile_text(value)?;
    if !suffix.is_ascii() {
        return Err(profile_parse_error());
    }

    let labels = suffix.strip_prefix('.').unwrap_or(&suffix);
    if labels.is_empty() || labels.len() > 253 {
        return Err(profile_parse_error());
    }

    for label in labels.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(profile_parse_error());
        }
    }

    Ok(suffix.to_ascii_lowercase())
}

fn required_envelope_identifier(value: &str) -> DomainResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(envelope_parse_error());
    }

    Ok(value.to_string())
}

fn required_profile_text(value: &str) -> DomainResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(profile_parse_error());
    }

    Ok(value.to_string())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

fn decode_standard_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
}

fn envelope_parse_error() -> DomainError {
    DomainError::new(
        SDWAN_DELIVERY_PARSE_FAILED_CODE,
        "signed delivery envelope is invalid",
    )
}

fn profile_parse_error() -> DomainError {
    DomainError::new(
        SDWAN_DELIVERY_PARSE_FAILED_CODE,
        "signed delivery profile is invalid",
    )
}

fn public_key_error() -> DomainError {
    DomainError::new(
        SDWAN_DELIVERY_PUBLIC_KEY_INVALID_CODE,
        "delivery public key must be exactly 32 bytes",
    )
}

fn payload_hash_error() -> DomainError {
    DomainError::new(
        SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE,
        "signed delivery payload hash is invalid",
    )
}

fn signature_error() -> DomainError {
    DomainError::new(
        SDWAN_DELIVERY_SIGNATURE_INVALID_CODE,
        "signed delivery signature is invalid",
    )
}

fn expired_error() -> DomainError {
    DomainError::new(
        SDWAN_DELIVERY_EXPIRED_CODE,
        "signed delivery envelope is expired",
    )
}
