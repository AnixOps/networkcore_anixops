//! Persistent identity-keyed floors for verified Windows tunnel deliveries.

use config_core::sdwan_delivery::VerifiedDeliveryEnvelope;
use config_core::windows_tunnel::{
    WINDOWS_TUNNEL_DELIVERY_INVALID_CODE, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE,
};
use control_domain::{DomainError, DomainResult};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

const LEDGER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverySequenceIdentity {
    tenant_id: String,
    bundle_kind: String,
    target_id: String,
}

impl DeliverySequenceIdentity {
    fn from_verified(envelope: &VerifiedDeliveryEnvelope) -> DomainResult<Self> {
        let identity = Self {
            tenant_id: envelope.tenant_id().to_string(),
            bundle_kind: envelope.bundle_kind().to_string(),
            target_id: envelope.target_id().to_string(),
        };
        if identity.is_valid() {
            Ok(identity)
        } else {
            Err(delivery_invalid_error())
        }
    }

    #[cfg(test)]
    fn for_test(tenant_id: &str, bundle_kind: &str, target_id: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            bundle_kind: bundle_kind.to_string(),
            target_id: target_id.to_string(),
        }
    }

    fn is_valid(&self) -> bool {
        is_canonical_identifier(&self.tenant_id)
            && is_canonical_identifier(&self.bundle_kind)
            && matches!(self.bundle_kind.as_str(), "client" | "pop")
            && is_canonical_identifier(&self.target_id)
    }
}

fn is_canonical_identifier(value: &str) -> bool {
    !value.is_empty() && value.trim() == value
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeliverySequenceFloors {
    pub(super) client: Option<u64>,
    pub(super) pop: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct NativeWindowsTunnelSequenceLedger;

impl NativeWindowsTunnelSequenceLedger {
    pub(super) fn read_floors(
        &self,
        client: &VerifiedDeliveryEnvelope,
        pop: &VerifiedDeliveryEnvelope,
    ) -> DomainResult<DeliverySequenceFloors> {
        let client_identity = DeliverySequenceIdentity::from_verified(client)?;
        let pop_identity = DeliverySequenceIdentity::from_verified(pop)?;
        self.store()?.read_floors(&client_identity, &pop_identity)
    }

    pub(super) fn reserve_pair(
        &self,
        client: &VerifiedDeliveryEnvelope,
        pop: &VerifiedDeliveryEnvelope,
    ) -> DomainResult<()> {
        let client_identity = DeliverySequenceIdentity::from_verified(client)?;
        let pop_identity = DeliverySequenceIdentity::from_verified(pop)?;
        self.store()?.reserve_pair(
            (&client_identity, client.sequence()),
            (&pop_identity, pop.sequence()),
        )
    }

    fn store(&self) -> DomainResult<SequenceLedgerStore> {
        let paths = platform_windows::tunnel_security::native_windows_prepare_tunnel_secure_paths()
            .map_err(|_| delivery_invalid_error())?;
        Ok(SequenceLedgerStore {
            path: paths.delivery_ledger_path,
        })
    }

    #[cfg(test)]
    fn for_test_path(path: PathBuf) -> SequenceLedgerStore {
        SequenceLedgerStore { path }
    }
}

#[derive(Debug, Clone)]
struct SequenceLedgerStore {
    path: PathBuf,
}

impl SequenceLedgerStore {
    fn read_floors(
        &self,
        client: &DeliverySequenceIdentity,
        pop: &DeliverySequenceIdentity,
    ) -> DomainResult<DeliverySequenceFloors> {
        self.with_locked_file(|file| {
            let journal = read_document(file)?;
            Ok(DeliverySequenceFloors {
                client: journal.document.floors.get(client).copied(),
                pop: journal.document.floors.get(pop).copied(),
            })
        })
    }

    fn reserve_pair(
        &self,
        client: (&DeliverySequenceIdentity, u64),
        pop: (&DeliverySequenceIdentity, u64),
    ) -> DomainResult<()> {
        self.with_locked_file(|file| {
            if client.0 == pop.0 || client.1 == 0 || pop.1 == 0 {
                return Err(delivery_invalid_error());
            }

            let mut journal = read_document(file)?;
            if journal
                .document
                .floors
                .get(client.0)
                .is_some_and(|floor| client.1 <= *floor)
                || journal
                    .document
                    .floors
                    .get(pop.0)
                    .is_some_and(|floor| pop.1 <= *floor)
            {
                return Err(sequence_replayed_error());
            }

            journal.document.floors.insert(client.0.clone(), client.1);
            journal.document.floors.insert(pop.0.clone(), pop.1);
            append_document(file, &journal)
        })
    }

    fn with_locked_file<T>(
        &self,
        operation: impl FnOnce(&mut File) -> DomainResult<T>,
    ) -> DomainResult<T> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|_| delivery_invalid_error())?;
        file.lock_exclusive()
            .map_err(|_| delivery_invalid_error())?;

        let result = operation(&mut file);
        if file.unlock().is_err() {
            return Err(delivery_invalid_error());
        }
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerDocument {
    schema_version: u32,
    // Structured identities serialize as ordered entries because JSON object keys are strings.
    #[serde(with = "sequence_floor_map")]
    floors: BTreeMap<DeliverySequenceIdentity, u64>,
}

struct LedgerJournal {
    document: LedgerDocument,
    last_complete_end: u64,
    has_trailing_partial: bool,
}

impl LedgerDocument {
    fn empty() -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            floors: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFloorEntry {
    identity: DeliverySequenceIdentity,
    sequence: u64,
}

mod sequence_floor_map {
    use super::{DeliverySequenceIdentity, LedgerFloorEntry};
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub(super) fn serialize<S>(
        floors: &BTreeMap<DeliverySequenceIdentity, u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries = floors
            .iter()
            .map(|(identity, sequence)| LedgerFloorEntry {
                identity: identity.clone(),
                sequence: *sequence,
            })
            .collect::<Vec<_>>();
        entries.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<DeliverySequenceIdentity, u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<LedgerFloorEntry>::deserialize(deserializer)?;
        let mut floors = BTreeMap::new();
        for entry in entries {
            if entry.sequence == 0 || !entry.identity.is_valid() {
                return Err(D::Error::custom("invalid delivery sequence floor"));
            }
            if floors.insert(entry.identity, entry.sequence).is_some() {
                return Err(D::Error::custom("duplicate delivery sequence identity"));
            }
        }
        Ok(floors)
    }
}

fn read_document(file: &mut File) -> DomainResult<LedgerJournal> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| delivery_invalid_error())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| delivery_invalid_error())?;
    if bytes.is_empty() {
        return Ok(LedgerJournal {
            document: LedgerDocument::empty(),
            last_complete_end: 0,
            has_trailing_partial: false,
        });
    }

    let mut latest = None;
    let mut record_start = 0;
    let mut last_complete_end = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }

        let record = &bytes[record_start..index];
        if record.is_empty() {
            return Err(delivery_invalid_error());
        }
        latest = Some(read_ledger_document(record)?);
        record_start = index + 1;
        last_complete_end = u64::try_from(record_start).map_err(|_| delivery_invalid_error())?;
    }

    if record_start < bytes.len() {
        let trailing_record = &bytes[record_start..];
        match serde_json::from_slice::<LedgerDocument>(trailing_record) {
            Ok(document) => {
                validate_ledger_document(document)?;
            }
            Err(error) if error.is_eof() => {}
            Err(_) => return Err(delivery_invalid_error()),
        }
    }

    Ok(LedgerJournal {
        document: latest.unwrap_or_else(LedgerDocument::empty),
        last_complete_end,
        has_trailing_partial: record_start < bytes.len(),
    })
}

fn read_ledger_document(record: &[u8]) -> DomainResult<LedgerDocument> {
    let document =
        serde_json::from_slice::<LedgerDocument>(record).map_err(|_| delivery_invalid_error())?;
    validate_ledger_document(document)
}

fn validate_ledger_document(document: LedgerDocument) -> DomainResult<LedgerDocument> {
    if document.schema_version != LEDGER_SCHEMA_VERSION {
        return Err(delivery_invalid_error());
    }
    Ok(document)
}

fn append_document(file: &mut File, journal: &LedgerJournal) -> DomainResult<()> {
    let bytes = serde_json::to_vec(&journal.document).map_err(|_| delivery_invalid_error())?;
    if journal.has_trailing_partial {
        file.set_len(journal.last_complete_end)
            .map_err(|_| delivery_invalid_error())?;
        file.seek(SeekFrom::Start(journal.last_complete_end))
            .map_err(|_| delivery_invalid_error())?;
    } else {
        file.seek(SeekFrom::End(0))
            .map_err(|_| delivery_invalid_error())?;
    }
    file.write_all(&bytes)
        .map_err(|_| delivery_invalid_error())?;
    file.write_all(b"\n")
        .map_err(|_| delivery_invalid_error())?;
    file.flush().map_err(|_| delivery_invalid_error())?;
    file.sync_all().map_err(|_| delivery_invalid_error())
}

fn delivery_invalid_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
        "signed tunnel delivery is invalid",
    )
}

fn sequence_replayed_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE,
        "delivery sequence is not newer than the persisted floor",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    struct TemporaryLedgerPath {
        path: PathBuf,
    }

    impl TemporaryLedgerPath {
        fn new() -> Self {
            let suffix = NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            Self {
                path: std::env::temp_dir().join(format!(
                    "networkcore-windows-sequence-ledger-{}-{timestamp}-{suffix}.json",
                    std::process::id()
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TemporaryLedgerPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn identity(tenant_id: &str, bundle_kind: &str, target_id: &str) -> DeliverySequenceIdentity {
        DeliverySequenceIdentity::for_test(tenant_id, bundle_kind, target_id)
    }

    fn test_ledger(path: &Path) -> SequenceLedgerStore {
        NativeWindowsTunnelSequenceLedger::for_test_path(path.to_path_buf())
    }

    fn valid_record(
        client: &DeliverySequenceIdentity,
        client_sequence: u64,
        pop: &DeliverySequenceIdentity,
        pop_sequence: u64,
    ) -> Vec<u8> {
        let mut floors = BTreeMap::new();
        floors.insert(client.clone(), client_sequence);
        floors.insert(pop.clone(), pop_sequence);
        serde_json::to_vec(&LedgerDocument {
            schema_version: LEDGER_SCHEMA_VERSION,
            floors,
        })
        .expect("valid ledger fixture serializes")
    }

    fn assert_delivery_invalid(result: DomainResult<DeliverySequenceFloors>) {
        let error = result.expect_err("malformed ledger is rejected");
        assert_eq!(error.code, WINDOWS_TUNNEL_DELIVERY_INVALID_CODE);
    }

    #[test]
    fn independent_client_and_pop_identities_reject_equal_and_lower_sequences() {
        let path = TemporaryLedgerPath::new();
        let ledger = test_ledger(path.path());
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        ledger
            .reserve_pair((&client, 3), (&pop, 4))
            .expect("first client/POP pair is accepted");

        let floors = ledger
            .read_floors(&client, &pop)
            .expect("persisted floors can be read");
        assert_eq!(floors.client, Some(3));
        assert_eq!(floors.pop, Some(4));

        let client_replay = ledger
            .reserve_pair((&client, 3), (&pop, 5))
            .expect_err("equal client sequence is rejected");
        assert_eq!(client_replay.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);

        let client_lower = ledger
            .reserve_pair((&client, 2), (&pop, 5))
            .expect_err("lower client sequence is rejected");
        assert_eq!(client_lower.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);

        let pop_replay = ledger
            .reserve_pair((&client, 4), (&pop, 4))
            .expect_err("equal POP sequence is rejected");
        assert_eq!(pop_replay.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);

        let pop_lower = ledger
            .reserve_pair((&client, 4), (&pop, 3))
            .expect_err("lower POP sequence is rejected");
        assert_eq!(pop_lower.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);
    }

    #[test]
    fn tenant_target_and_bundle_kind_are_independent_identity_keys() {
        let path = TemporaryLedgerPath::new();
        let ledger = test_ledger(path.path());
        let base_client = identity("tenant-a", "client", "device-a");
        let base_pop = identity("tenant-a", "pop", "pop-a");
        ledger
            .reserve_pair((&base_client, 7), (&base_pop, 11))
            .expect("base pair is accepted");

        for alternate_client in [
            identity("tenant-b", "client", "device-a"),
            identity("tenant-a", "client", "device-b"),
            identity("tenant-a", "pop", "device-a"),
        ] {
            let floors = ledger
                .read_floors(&alternate_client, &base_pop)
                .expect("different identity does not collide");
            assert_eq!(floors.client, None);
            assert_eq!(floors.pop, Some(11));
        }
    }

    #[test]
    fn reopening_the_same_ledger_path_preserves_sequence_floors() {
        let path = TemporaryLedgerPath::new();
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        test_ledger(path.path())
            .reserve_pair((&client, 3), (&pop, 4))
            .expect("initial reservation succeeds");
        let reopened = test_ledger(path.path());
        let floors = reopened
            .read_floors(&client, &pop)
            .expect("reopened ledger preserves floors");
        assert_eq!(floors.client, Some(3));
        assert_eq!(floors.pop, Some(4));
    }

    #[test]
    fn trailing_partial_record_does_not_erase_the_last_durable_floor() {
        let path = TemporaryLedgerPath::new();
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");
        test_ledger(path.path())
            .reserve_pair((&client, 3), (&pop, 4))
            .expect("initial reservation succeeds");

        let mut file = OpenOptions::new()
            .append(true)
            .open(path.path())
            .expect("test can append a partial record");
        file.write_all(b"{\"schema_version\":1")
            .expect("test can write a trailing partial record");
        drop(file);

        let reopened = test_ledger(path.path());
        let floors = reopened
            .read_floors(&client, &pop)
            .expect("trailing partial record is ignored");
        assert_eq!(floors.client, Some(3));
        assert_eq!(floors.pop, Some(4));
    }

    #[test]
    fn no_newline_garbage_fails_closed() {
        let path = TemporaryLedgerPath::new();
        fs::write(path.path(), b"not a delivery sequence ledger")
            .expect("test can write unterminated garbage");
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        assert_delivery_invalid(test_ledger(path.path()).read_floors(&client, &pop));
    }

    #[test]
    fn complete_invalid_schema_without_newline_fails_closed() {
        let path = TemporaryLedgerPath::new();
        fs::write(path.path(), br#"{"schema_version":2,"floors":[]}"#)
            .expect("test can write an unterminated schema fixture");
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        assert_delivery_invalid(test_ledger(path.path()).read_floors(&client, &pop));
    }

    #[test]
    fn unknown_identity_fields_fail_closed() {
        let path = TemporaryLedgerPath::new();
        fs::write(
            path.path(),
            br#"{"schema_version":1,"floors":[{"identity":{"tenant_id":"tenant-a","bundle_kind":"client","target_id":"device-a","unexpected":"value"},"sequence":3}]}"#,
        )
        .expect("test can write an unknown-field fixture");
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        assert_delivery_invalid(test_ledger(path.path()).read_floors(&client, &pop));
    }

    #[test]
    fn unsupported_bundle_kind_fails_closed() {
        let path = TemporaryLedgerPath::new();
        fs::write(
            path.path(),
            br#"{"schema_version":1,"floors":[{"identity":{"tenant_id":"tenant-a","bundle_kind":"gateway","target_id":"device-a"},"sequence":3}]}"#,
        )
        .expect("test can write an unsupported-bundle fixture");
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        assert_delivery_invalid(test_ledger(path.path()).read_floors(&client, &pop));
    }

    #[test]
    fn boundary_whitespace_in_identity_fields_fails_closed() {
        let path = TemporaryLedgerPath::new();
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        for (tenant_id, bundle_kind, target_id) in [
            (" tenant-a", "client", "device-a"),
            ("tenant-a", "client ", "device-a"),
            ("tenant-a", "client", "device-a "),
        ] {
            let record = format!(
                r#"{{"schema_version":1,"floors":[{{"identity":{{"tenant_id":"{tenant_id}","bundle_kind":"{bundle_kind}","target_id":"{target_id}"}},"sequence":3}}]}}"#
            );
            fs::write(path.path(), record).expect("test can write a whitespace fixture");

            assert_delivery_invalid(test_ledger(path.path()).read_floors(&client, &pop));
        }
    }

    #[test]
    fn complete_valid_v1_record_without_final_newline_is_an_uncommitted_recoverable_tail() {
        let path = TemporaryLedgerPath::new();
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");
        test_ledger(path.path())
            .reserve_pair((&client, 3), (&pop, 4))
            .expect("initial reservation succeeds");

        let mut file = OpenOptions::new()
            .append(true)
            .open(path.path())
            .expect("test can append a complete unterminated record");
        file.write_all(&valid_record(&client, 99, &pop, 100))
            .expect("test can write a complete unterminated record");
        drop(file);

        let floors = test_ledger(path.path())
            .read_floors(&client, &pop)
            .expect("complete unterminated tail preserves the durable replay floor");
        assert_eq!(floors.client, Some(3));
        assert_eq!(floors.pop, Some(4));

        test_ledger(path.path())
            .reserve_pair((&client, 5), (&pop, 6))
            .expect("newer pair replaces only the known unterminated tail");
        let floors = test_ledger(path.path())
            .read_floors(&client, &pop)
            .expect("recovered journal remains readable");
        assert_eq!(floors.client, Some(5));
        assert_eq!(floors.pop, Some(6));
        let bytes = fs::read(path.path()).expect("test can inspect recovered record");
        assert!(bytes.ends_with(b"\n"));
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    #[test]
    fn eof_only_json_prefix_recovers_the_last_complete_record() {
        let path = TemporaryLedgerPath::new();
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");
        test_ledger(path.path())
            .reserve_pair((&client, 3), (&pop, 4))
            .expect("initial reservation succeeds");

        let mut file = OpenOptions::new()
            .append(true)
            .open(path.path())
            .expect("test can append an EOF-only JSON prefix");
        file.write_all(b"{\"schema_version\":1")
            .expect("test can write an EOF-only JSON prefix");
        drop(file);

        let floors = test_ledger(path.path())
            .read_floors(&client, &pop)
            .expect("EOF-only prefix does not erase the prior replay floor");
        assert_eq!(floors.client, Some(3));
        assert_eq!(floors.pop, Some(4));
    }

    #[test]
    fn new_reservation_recovers_a_trailing_partial_without_losing_the_prior_floor() {
        let path = TemporaryLedgerPath::new();
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");
        test_ledger(path.path())
            .reserve_pair((&client, 3), (&pop, 4))
            .expect("initial reservation succeeds");

        let mut file = OpenOptions::new()
            .append(true)
            .open(path.path())
            .expect("test can append a partial record");
        file.write_all(b"{\"schema_version\":1")
            .expect("test can write a trailing partial record");
        drop(file);

        let replay = test_ledger(path.path())
            .reserve_pair((&client, 3), (&pop, 4))
            .expect_err("prior complete record remains the replay floor");
        assert_eq!(replay.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);

        test_ledger(path.path())
            .reserve_pair((&client, 5), (&pop, 6))
            .expect("newer reservation replaces only the trailing partial record");
        let floors = test_ledger(path.path())
            .read_floors(&client, &pop)
            .expect("recovered journal remains readable");
        assert_eq!(floors.client, Some(5));
        assert_eq!(floors.pop, Some(6));

        let bytes = fs::read(path.path()).expect("test can inspect the recovered journal");
        assert!(bytes.ends_with(b"\n"));
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    #[test]
    fn malformed_complete_record_fails_closed_without_exposing_its_path() {
        let path = TemporaryLedgerPath::new();
        fs::write(path.path(), b"{ malformed ledger\n")
            .expect("test can write malformed ledger fixture");
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        let error = test_ledger(path.path())
            .read_floors(&client, &pop)
            .expect_err("malformed ledger is rejected");
        assert_eq!(
            error.code,
            config_core::windows_tunnel::WINDOWS_TUNNEL_DELIVERY_INVALID_CODE
        );
        assert!(!error.message.contains(&path.path().display().to_string()));
    }

    #[test]
    fn concurrent_same_pair_reservations_admit_once_and_replay_once() {
        let path = TemporaryLedgerPath::new();
        let ledger = Arc::new(test_ledger(path.path()));
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let ledger = Arc::clone(&ledger);
            let client = client.clone();
            let pop = pop.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                ledger.reserve_pair((&client, 3), (&pop, 4))
            }));
        }
        barrier.wait();

        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("reservation thread completes"))
            .collect::<Vec<_>>();
        let successful_reservations = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        let replayed_reservations = outcomes
            .iter()
            .filter(|outcome| match outcome {
                Ok(()) => false,
                Err(error) => error.code == WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE,
            })
            .count();

        assert_eq!(successful_reservations, 1);
        assert_eq!(replayed_reservations, 1);
    }
}
