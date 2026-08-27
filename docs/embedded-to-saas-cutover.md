# Embedded Identity to SaaS cutover

This runbook moves one Identity workspace from Module storage to the standalone
Identity service. It is intentionally a single-writer procedure: the source is
frozen before export and must never be released after the target has accepted
production writes.

## Preconditions

- Source and target run compatible, immutable Identity releases and report the
  same `schema_version` and `metadata_schema_sha256`.
- A verified, encrypted source backup exists together with the Identity
  manifest, signing-key version inventory, data-key version inventory, and
  service artifact checksum.
- The SaaS target workspace contains no portable Identity records.
- Every OIDC/SAML provider is configured on the target. Provider secrets are
  provisioned through the target secret store and are never copied in the
  portability bundle.
- Runtime has the target endpoint, issuer, audience, service credential, and
  JWKS trust configuration ready but has not switched traffic.
- `IDENTITY_OPERATIONS_ACCESS_TOKEN` is stored as an operations secret. In
  production, `/ops/**` is reachable only on `HTTP_OPS_ADDR`; public exposure
  requires the explicit break-glass configuration and reason.

The operations API uses `Authorization: Bearer <operations token>`. Save every
request ID, response, bundle checksum, and approval/change ticket in the
cutover evidence record.

## Procedure

1. Dry-run the source inventory with
   `POST /ops/identity-portability/exports` and:

   ```json
   {
     "workspace_id": "workspace-a",
     "source_mode": "module",
     "dry_run": true
   }
   ```

   Review portable dataset counts and excluded counts. Password credentials,
   refresh sessions, MFA secrets, authorization codes, login transactions, and
   provider secrets must be excluded.

2. Dry-run the empty target and confirm all provider keys can be made ready.
   Do not start the import if the target contains any portable dataset rows.

3. Freeze source writes with
   `POST /ops/identity-portability/write-fences`:

   ```json
   {
     "workspace_id": "workspace-a",
     "evidence": "approved-change-ticket-and-backup-reference",
     "operator": "operator-id"
   }
   ```

   The same evidence is idempotent. A different evidence value cannot replace
   an active fence. Identity rejects subsequent authentication mutations,
   credential/session mutations, Catalog publication, and management writes
   for this workspace. Reads remain available.

4. Export with the exact, unhashed evidence value from step 3:

   ```json
   {
     "workspace_id": "workspace-a",
     "source_mode": "module",
     "freeze_evidence": "approved-change-ticket-and-backup-reference",
     "dry_run": false
   }
   ```

   Store the returned bundle in encrypted, access-controlled temporary storage.
   Verify that `content_sha256`, `authorization_state_sha256`,
   `metadata_schema_sha256`, and `export_id` are present. Repeating the export
   while the source is unchanged must produce the same content checksum and
   export ID.

5. Dry-run the target import using the complete bundle, a stable idempotency
   key, explicit provider readiness, and all three security acknowledgements:

   ```json
   {
     "bundle": { "contract_version": "domainry-identity-portability-v1" },
     "idempotency_key": "approved-cutover-id",
     "dry_run": true,
     "provider_readiness": { "oidc": true },
     "accept_session_revocation": true,
     "accept_credential_reset": true,
     "accept_mfa_reenrollment": true
   }
   ```

   `bundle` above represents the complete exported object, not only the shown
   field. The target verifies the bundle checksum, provider configuration
   hashes, target metadata hash, and target emptiness before any write.

6. Submit the same request with `dry_run: false`. The import runs in one target
   database transaction. It re-exports the inserted target records inside that
   transaction and compares the server-computed authorization-state digest to
   the source digest before commit. A repeated request with the same
   idempotency key returns the existing receipt only after verifying that the
   target has not drifted.

7. Reconcile before traffic switch:

   - every portable dataset count equals the export inventory;
   - the receipt content checksum equals the bundle checksum;
   - `authorization_parity_verified` is true;
   - `sessions_revoked`, `credentials_reset_required`, and
     `mfa_reenrollment_required` are true;
   - target OIDC/SAML provider setup checks pass using target-held secrets;
   - discovery, issuer, audience, JWKS, and Remote SDK conformance checks pass;
   - representative administrators and restricted roles receive the same
     menus, function permissions, data scopes, and field/reference/export
     policies.

8. Switch Runtime configuration to SaaS, restart/drain Runtime instances in the
   approved order, and verify login, refresh rotation, logout, local token
   verification, Catalog revision, access-bundle resolution, and high-risk
   reauthorization. Keep the source database and its active write fence
   recoverable for the agreed retention window.

## Rollback boundary

- Before Runtime traffic switches, or before the target accepts any production
  mutation, rollback may discard the target attempt and release the source
  fence with
  `POST /ops/identity-portability/write-fences/{workspaceID}/release` and an
  operator identity.
- After any target production mutation, never release the old source fence.
  The old source is stale. Roll forward on SaaS, or perform a separately
  approved reverse migration from a newly frozen SaaS source. Dual writes and
  copying only the changed rows are forbidden.

Every freeze and release is recorded in the append-only
`identity_portability_write_fence_events` ledger; current enforcement state is
the `identity_workspace_write_fences` projection. Export/import receipts and
the event ledger must be retained with the cutover evidence.

## External-provider drill

Before production approval, run at least one real OIDC and one real SAML login
against the target environment. Confirm exact redirect matching, OIDC issuer,
signature, audience, nonce, state and PKCE validation, and SAML issuer,
audience, destination/recipient, request correlation, time window, signature,
and assertion replay rejection. Confirm that the resulting Domainry
authorization code is single-use and that no upstream access token reaches the
Runtime or browser application state.
