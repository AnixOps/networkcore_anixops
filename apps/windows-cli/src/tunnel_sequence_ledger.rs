//! Test contracts for the identity-keyed Windows tunnel delivery sequence ledger.

#[cfg(test)]
mod tests {
    use super::*;
    use config_core::windows_tunnel::WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

    struct TemporaryLedgerPath {
        path: PathBuf,
    }

    impl TemporaryLedgerPath {
        fn new() -> Self {
            let suffix = NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
            Self {
                path: std::env::temp_dir().join(format!(
                    "networkcore-windows-sequence-ledger-{}-{suffix}.json",
                    std::process::id()
                )),
            }
        }

        fn path(&self) -> &std::path::Path {
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

    fn test_ledger(path: &std::path::Path) -> NativeWindowsTunnelSequenceLedger {
        NativeWindowsTunnelSequenceLedger::for_test_path(path.to_path_buf())
    }

    #[test]
    fn independent_client_and_pop_identities_reserve_first_sequences_and_reject_replay() {
        let path = TemporaryLedgerPath::new();
        let ledger = test_ledger(path.path());
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        ledger
            .reserve_pair((&client, 1), (&pop, 1))
            .expect("first client/POP pair is accepted");

        let floors = ledger
            .read_floors(&client, &pop)
            .expect("persisted floors can be read");
        assert_eq!(floors.client, Some(1));
        assert_eq!(floors.pop, Some(1));

        let client_replay = ledger
            .reserve_pair((&client, 1), (&pop, 2))
            .expect_err("equal client sequence is rejected");
        assert_eq!(client_replay.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);

        let pop_replay = ledger
            .reserve_pair((&client, 2), (&pop, 1))
            .expect_err("equal POP sequence is rejected");
        assert_eq!(pop_replay.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);
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
            identity("tenant-a", "client-alt", "device-a"),
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
    fn malformed_ledger_fails_closed_without_exposing_its_path() {
        let path = TemporaryLedgerPath::new();
        fs::write(path.path(), b"{ malformed ledger")
            .expect("test can write malformed ledger fixture");
        let client = identity("tenant-a", "client", "device-a");
        let pop = identity("tenant-a", "pop", "pop-a");

        let error = test_ledger(path.path())
            .read_floors(&client, &pop)
            .expect_err("malformed ledger is rejected");
        assert_eq!(error.code, config_core::windows_tunnel::WINDOWS_TUNNEL_DELIVERY_INVALID_CODE);
        assert!(!error.message.contains(&path.path().display().to_string()));
    }
}
