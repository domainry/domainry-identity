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

1. Submit a dry-run export through the host Data Exchange transport using
   provider `identity-portability` and these provider options:

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

2. Prepare the empty target. Configure every referenced provider and its secret
   on the target; Identity validates the actual configuration before import.
   Do not start the import if the target contains any portable dataset rows.

3. Freeze source writes with
   `POST /identity/portability/write-fences`:

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

4. Submit the export through Data Exchange. Identity checks the durable frozen
   state directly, so the export request does not repeat the change reference:

   ```json
   {
     "workspace_id": "workspace-a",
     "source_mode": "module",
     "dry_run": false
   }
   ```

   Download the completed Data Exchange artifact into encrypted,
   access-controlled temporary storage.
   Verify that `content_sha256`, `authorization_state_sha256`,
   `metadata_schema_sha256`, and `export_id` are present. Repeating the export
   while the source is unchanged must produce the same content checksum and
   export ID.

5. Submit the complete JSON bundle to Data Exchange provider
   `identity-portability` with a stable job idempotency key. The engine's
   validation phase is the dry run; Identity needs no caller-supplied import
   options. The target verifies the bundle checksum, actual provider
   configuration and secrets, target metadata hash, and target emptiness
   before any write.

6. After validation succeeds, the Identity provider applies the import in one
   target database transaction. It
   re-exports the inserted target records inside that transaction and compares
   the server-computed authorization-state digest to the source digest before
   commit. Data Exchange owns job idempotency, chunks, retries, and the durable
   artifact; Identity owns the domain validation and transactional apply.

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
  `POST /identity/portability/write-fences/{workspaceID}/release` and an
  operator identity.
- After any target production mutation, never release the old source fence.
  The old source is stale. Roll forward on SaaS, or perform a separately
  approved reverse migration from a newly frozen SaaS source. Dual writes and
  copying only the changed rows are forbidden.

Every freeze and release is recorded in the shared append-only `_audit_events`
ledger; current enforcement state is the `_identity_workspace_write_fences`
projection. Data Exchange job and artifact evidence plus the Audit events must
be retained with the cutover evidence.

## External-provider drill

Before production approval, run at least one real OIDC and one real SAML login
against the target environment. Confirm exact redirect matching, OIDC issuer,
signature, audience, nonce, state and PKCE validation, and SAML issuer,
audience, destination/recipient, request correlation, time window, signature,
and assertion replay rejection. Confirm that the resulting Domainry
authorization code is single-use and that no upstream access token reaches the
Runtime or browser application state.
