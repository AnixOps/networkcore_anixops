# Windows Stage 4 POP Peer Manual Acceptance

> Status: pending implementation and manual acceptance. This document defines the operator
> topology and evidence boundary for signed POP peer identity and structured EasyTier readiness.
> It does not authorize production routing changes or mark a release as accepted.

## Scope

Stage 4 binds the selected POP's signed EasyTier peer ID to the peer observed by the Windows
runtime. The Windows client must accept readiness only when the expected remote peer appears in
the local EasyTier CLI JSON result; its own `cost: Local` row is not evidence that the selected
POP is connected.

The implementation is not complete yet. This document prepares the test environment and defines
the evidence required after the implementation, CI, and review gates are complete.

## Recommended Topology

Use three roles. They do not require three new physical machines.

| Role | Required host | EasyTier role | Purpose |
| --- | --- | --- | --- |
| Linux A | Existing or dedicated Linux POP | Selected remote POP | Joins the existing cluster, owns the selected POP peer ID, and routes the controlled test subnet. |
| Linux B | Existing or dedicated Linux test target behind Linux A | Not required by default | Hosts a controlled ICMP and HTTP target in the POP-routed test subnet. |
| Windows C | Dedicated Windows terminal | Endpoint client | Runs the externally supplied, pinned EasyTier runtime and NetworkCore foreground tunnel. |

The intended path is:

```text
Windows C -- EasyTier overlay --> Linux A (selected POP) --> Linux B test subnet
```

Linux B may be an existing Linux machine if it is reachable only through Linux A's advertised
test CIDR. It does not need to run EasyTier. If the existing cluster has no suitable target,
create a small isolated Linux VM for Linux B.

Windows C plus Linux A alone is sufficient only to prove that the expected peer is present. It is
not sufficient for the full acceptance because it cannot prove that the signed route and traffic
policy actually pass through the selected POP. A Linux B target directly reachable as another
overlay peer is also insufficient; it must sit behind the POP-routed test subnet.

## Environment Preparation

All tests use a dedicated tenant, test network identity, test CIDR, and test service. Do not use
production destinations, production secrets, customer traffic, or public management ports.

### Linux A: Selected POP

1. Select one existing EasyTier Linux POP and record its stable numeric peer ID in protected
   operator evidence.
2. Keep the EasyTier RPC portal local to the host or a separately protected management network.
   Do not expose it to the Internet. The paired CLI must be able to query the configured local
   portal.
3. Record the approved core and CLI version, artifact SHA-256 values, and a redacted result of:

   ```text
   easytier-cli --rpc-portal <local-rpc-address> --output json peer
   ```

4. Configure Linux A to route exactly one controlled test CIDR to Linux B. Ensure Windows C has
   no independent direct route to that CIDR.
5. Confirm that Linux A can reach Linux B before involving the Windows client.

### Linux B: POP-Routed Test Target

1. Place Linux B in the controlled test CIDR behind Linux A.
2. Provide a minimal deterministic HTTP response and ICMP reachability for the test only.
3. Restrict the service firewall to the test path where practical. Do not expose a general-purpose
   service or production credentials.
4. Record only the test CIDR and service outcome in the protected evidence record; do not commit
   a real address or topology to this repository.

### Windows C: Endpoint Client

1. Use an elevated Windows test terminal with no unrelated VPN or route-management software
   active during the acceptance window.
2. Stage the approved external EasyTier core, CLI, and loader sidecars under the protected
   ProgramData root required by the foreground tunnel manual gate. Record ACL and SHA-256
   evidence outside the repository.
3. Keep the EasyTier RPC portal local to Windows C. NetworkCore must call the explicitly pinned
   CLI, never discover a binary from `PATH`.
4. Prepare a dedicated signed client profile and POP profile after Stage 4 implementation is
   available. Both profiles must carry the same canonical EasyTier peer ID for Linux A.

## Manual Acceptance Sequence

Run this sequence only after the Stage 4 implementation commit has an exact successful GitHub
Actions CI run and a fresh review.

1. Record the candidate commit SHA, CI run URL, Windows version, selected POP logical ID, and
   the protected Linux A peer-ID evidence.
2. Record Windows C pre-start physical adapter, route table, and the absence of the session-owned
   destination and endpoint-bypass tuples.
3. Verify the signed client and POP profiles contain the same canonical peer ID for Linux A.
4. Start the foreground tunnel with the explicitly approved artifact paths and hashes.
5. Capture a redacted `--output json peer` result on Windows C. It must contain exactly one
   matching non-`Local` peer record for Linux A. A Local row, malformed JSON, multiple-instance
   wrapper, missing expected ID, or different ID is a failure.
6. Verify the signed test CIDR route and perform ICMP and HTTP checks from Windows C to Linux B.
   Record the expected negative result for an unadvertised test CIDR.
7. With a test-only signed envelope whose POP peer ID is different from Linux A, confirm that
   readiness fails before route activation. Never use a production signing private key for this
   negative case.
8. Run tunnel status, then stop with the explicit confirmation. Prove that session-owned routes,
   endpoint bypasses, state, and process ownership return to the documented pre-start state.
9. Keep all detailed route tuples, process identifiers, RPC addresses, raw JSON, secrets, and
   full topology in protected operator evidence only.

## Evidence Record Template

Store this record outside Git. Replace bracketed fields with redacted operator values.

```text
stage4-pop-peer-acceptance-status=pending|passed|failed
candidate-commit=[commit-sha]
ci-run=[github-actions-url]
selected-pop-logical-id=[logical-id]
selected-pop-peer-id=[protected-reference]
linux-a-core-version=[version]
linux-a-cli-version=[version]
windows-core-sha256=[sha256]
windows-cli-sha256=[sha256]
windows-peer-json-result=[redacted-pass|redacted-fail]
test-cidr=[protected-reference]
positive-ping=[pass|fail]
positive-http=[pass|fail]
unadvertised-cidr-negative-test=[pass|fail]
wrong-peer-id-negative-test=[pass|fail]
stop-cleanup-proof=[pass|fail]
operator=[operator-id]
recorded-at=[utc-timestamp]
```

`passed` is permitted only when every required positive, negative, and cleanup proof passes.
Otherwise keep the status as `failed` or `pending`, preserve the evidence, and do not treat the
Windows tunnel as production-ready.

## Explicit Non-Goals

- This acceptance does not install a Windows driver, service, or installer.
- This acceptance does not expose EasyTier RPC on a public interface.
- This acceptance does not test arbitrary cluster routes, multi-hop policy execution, DNS changes,
  full-tunnel behavior, or iOS clients.
- This document does not replace the existing Windows foreground tunnel ACL, route ownership, and
  cleanup manual gate in `docs/manual-intervention.md`.
