# Identity StoreOrganizationDelivery v1

`StoreOrganizationDelivery` is Identity's purpose-specific, non-HTTP capability
for Runtime-generated store-management handlers. It creates, renames, disables,
resolves, and lists store OrganizationUnits without exposing generic Identity
organization CRUD or a database transaction to project code.

Workspace is the only tenant and isolation boundary. A store is an
`IdentityOrganizationUnit` with `node_type=store` inside that Workspace. This
capability does not accept or derive TenantID, does not create a tenant registry
or tenant-to-Workspace mapping, and treats names such as `tenant_admin` only as
project role keys.

## Stable SDK surface

The public contract is in the sibling SDK:

- `identity/store_organization_delivery.go` owns the v1 request/result and
  minimal projection types.
- `sdk.go` exposes `StoreOrganizationDeliveryBinding` for the core and
  `StoreOrganizationDeliveryUnitOfWorkBinder` /
  `EmbeddedStoreOrganizationDeliveryBinding` for Runtime infrastructure.

The contract version is
`domainry-identity-store-organization-delivery-v1`.

Embedded Runtime infrastructure must discover
`EmbeddedStoreOrganizationDeliveryBinding`, bind the current host-owned
`EmbeddedTransaction{Executor: actionTransaction}`, and inject only the returned
`StoreOrganizationDelivery` into project code. It must not inject the binder,
transaction executor, database, or full Identity Binding. `actionTransaction`
may be a real `*sql.Tx` or a domainry-orm `driver.Transaction`, including
SQLite's immediate transaction implementation; a `*sql.DB` or bare connection
is rejected. The embedded module does not implement the unbound
`StoreOrganizationDeliveryBinding`, so generated handlers cannot accidentally
start a separate Identity transaction.

There is no HTTP callback or public StoreOrganizationDelivery route. If the host
transaction cannot be joined, fail with
`identity.store_organization_delivery_transaction_required`.

## Exact permissions

- `identity.store_organization_delivery.create`
- `identity.store_organization_delivery.rename`
- `identity.store_organization_delivery.disable`
- `identity.store_organization_delivery.resolve`
- `identity.store_organization_delivery.list`

All five are Identity-owned non-HTTP Actions. Grants retain their exact `all`,
`org`, `org_child`, or `target_org` data scope. Create authorizes against the
persisted company parent; rename/disable/resolve authorize against the persisted
store ID; list applies the scope inside the repository query.

These grants do not imply `identity.organization_units.*`, and generic
organization CRUD grants do not authorize this capability. Runtime obtains the
actor, Workspace, role grants, scope tree, and authorization revision from the
verified bearer and persisted Identity state. None is accepted from the project
request.

## Mutation rules

Create requires an ID, code, name, company parent ID, zero expected version, and
an idempotency key. The request has no `node_type`: Identity always writes
`store`. The parent must be a persisted, active `company` node in the same
Workspace. A store or cross-Workspace record cannot be used as the parent.

The create ID is Runtime-supplied and opaque to Identity. Identity preserves the
trimmed value as the canonical OrganizationUnit ID, includes it in the request
fingerprint, and returns it unchanged. Repeating the same request and
idempotency key in the same or a later UoW returns the durable replay result;
reusing the key with another ID fails, and attempting to create an existing ID
under another key fails the create CAS check.

Rename requires only store ID, new name, and current version. Disable requires
only store ID and current version. Those operations cannot change code, parent,
node type, sort order, path, or ancestors. Identity derives and preserves the
canonical hierarchy.

CAS versions and a canonical state fingerprint live in
`_identity_store_organization_states`; the table contains concurrency evidence,
not a duplicate organization projection. An existing store first adopted by
the capability has logical version 1. A mutation whose expected version is
stale fails with `backend.identity.store_organization_version_conflict`. If an
administrator changes the canonical OrganizationUnit through another path after
adoption, the fingerprint mismatch fails closed with
`backend.identity.store_organization_external_change` instead of overwriting it.

The idempotency receipt is stored in
`_identity_store_organization_deliveries`, scoped by Workspace. The request
fingerprint includes the server-derived actor and application audience. Exact
replay returns the original result with `Replayed=true`; same-key/different-body
reuse returns `backend.idempotency_key_reused`. Authorization is checked again on
replay. Create replay re-reads the current Store, its delivery CAS state, and its
company parent; verifies that the receipt parent still matches the persisted
parent and that the parent remains an active company; then reapplies the current
create permission scope to that company parent. This preserves `org` and
`target_org` semantics without trusting the receipt or incorrectly authorizing
against the child Store ID. Rename and disable replay continue to authorize
against the Store ID. Removed permissions, scope changes, missing/corrupt state,
or external parent/type/status changes fail closed, and replay performs no
write or duplicate audit append.

Organization mutation, CAS evidence, receipt, and audit event share the host
executor. A downstream business-handler failure therefore rolls back every
Identity effect. Restart reads the durable receipt and returns the same delivery
ID without repeating the mutation.

## Minimal read projection

`ResolveStoreOrganization` and each `ListStoreOrganizations` page return only:

- ID, code, current name, active/disabled status, and CAS version;
- company parent ID, canonical path, ancestor IDs, depth, and sort order.

They return store nodes only. Runtime may compose these trusted values into a
NightPOS store-configuration DTO; browser-supplied names, status, hierarchy, or
scope are not authority.

The list request is an explicit bounded contract:

- `page_size=0` selects the default of 50; accepted explicit values are 1–100;
- `cursor` is an opaque Identity-issued stable-ID keyset cursor;
- the result is `{items, next_cursor}`, with an empty `next_cursor` only when no
  later authorized row exists.

Persistence performs Workspace restriction, `node_type=store`, the exact list
permission's compiled organization data scope, company-parent integrity, CAS
version projection, `id ASC` cursor comparison, and `LIMIT page_size+1` in one
domainry-orm query. It does not load all OrganizationUnits and filter in Go, and
does not issue per-store parent or version queries. A cursor is only a lower
bound: the current permission scope is reapplied on every page, so a cursor
obtained under a broader grant cannot widen a narrower grant.

## Identity implementation and tests

- `internal/application/identity/identity_store_organization_delivery_application_service.go`
- `internal/infrastructure/persistence/database/identity/identity_store_organization_delivery_store.go`
- `internal/adapter/identitysdk/store_organization_delivery.go`
- `internal/assembly/module/store_organization_delivery.go`
- `internal/assembly/identity_store_organization_delivery_integration_test.go`
- `internal/application/identity/identity_store_organization_delivery_scope_test.go`
- `internal/infrastructure/persistence/database/identity/integrationtest/identity_store_organization_page_integration_test.go`

Schema ownership remains with Identity and contributes migration v3 through the
host registrar and the host's sole `_schema_migrations` ledger.

## External integration gaps

No Runtime, Plane, or NightPosNew code is changed here. Their owners still need
to upgrade the sibling SDK, bind this capability inside the Runtime Action UoW,
inject only the returned narrow interface, publish the five exact permissions
with the desired NightPOS role scopes, pass `page_size`/opaque `cursor` through
unchanged, consume `items`/`next_cursor`, and compose the resolve/list projection
into NightPOS DTOs. They must not add TenantID, invent offset pagination, inspect
cursor contents, or substitute generic Identity organization CRUD.
