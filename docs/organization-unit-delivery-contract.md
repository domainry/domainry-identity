# Identity OrganizationUnitDelivery v1

`OrganizationUnitDelivery` is Identity's narrow, non-HTTP capability for
Runtime-generated handlers that need a real node in the Identity organization
tree. It is not generic organization management CRUD and does not contain any
CRM, M1, department-table, or quota-specific behavior.

The V1 contract is
`domainry-identity-organization-unit-delivery-v1`. Its source-owned Go surface
is `github.com/domainry/domainry-identity/organizationunit`; the public
`github.com/domainry/domainry-identity/module` facade aliases the same request,
result, permission, and interface types.

## Operations and types

`Delivery` has exactly two methods:

```go
CreateOrganizationUnit(context.Context, DeliveryRequest) (DeliveryResult, error)
ResolveOrganizationUnit(context.Context, ResolveRequest) (DeliveredOrganizationUnit, error)
```

Create accepts the Runtime-owned stable opaque ID, code, name, node type,
persisted parent ID, sort order, zero expected version, access token, and
idempotency key. Identity derives active status, path, ancestors, and depth.
The V1 delivery child types are `region`, `department`, `team`, and `warehouse`.
`company` remains root-only. `store` remains exclusively owned by the existing
purpose-specific `StoreOrganizationDelivery`, so this capability cannot bypass
store hierarchy or quota policy.

Resolve accepts only an organization ID and expected node type. It does not
accept a parent ID. Identity joins the requested node to its real persisted,
active parent inside the current Workspace and applies authorization to that
parent in the same repository query. A caller therefore cannot discover an
untrusted parent and cannot forge one to widen its scope.

Both operations return the canonical ID, code, name, node type, status, parent
ID, path, ancestor IDs, depth, sort order, and delivery version. Creates start
at version 1.

## Embedded Runtime binding

The deployment-neutral core implements `organizationunit.Binding`. An embedded
module deliberately does not expose that unbound capability. Runtime must type
assert the returned module Binding to `organizationunit.EmbeddedBinding`, call
`OrganizationUnitDeliveryUnitOfWorkBinder`, and bind an
`identitysdk.EmbeddedTransaction`:

```go
embedded := binding.(organizationunit.EmbeddedBinding)
delivery, err := embedded.OrganizationUnitDeliveryUnitOfWorkBinder().
    BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{
        Executor: actionTransaction,
    })
```

Only the returned `organizationunit.Delivery` belongs in generated project
code. The binder, transaction carrier, executor, and database handle are
infrastructure-only. A pool or bare connection is rejected with
`identity.organization_unit_delivery_transaction_required`.

The module descriptor advertises `organization_unit_delivery` when available.

## Authorization and isolation

The source-owned exact permissions are:

- `identity.organization_unit_delivery.create`
- `identity.organization_unit_delivery.resolve`

These permissions do not imply `identity.organization_units.*` or
`identity.store_organization_delivery.*`, and those grants do not authorize
this capability.

Identity verifies the bearer token, application audience, fixed module
Workspace, registered application, actor, and authorization revision. Create
applies the exact permission's compiled data scope to the requested persisted
parent both before and during the final write. Resolve derives the persisted
parent and applies the compiled data scope in its SQL query. Every read and
write is explicitly Workspace-scoped.

The parent must exist in the current Workspace, have a recognized Identity
node type, and be active. The canonical organization validator rejects missing
IDs, code/name/type errors, cycles, a duplicate code anywhere in the Workspace,
and a duplicate sibling name. The existing case-insensitive sibling-name
invariant is also enforced by the canonical table's bounded `sibling_key`
unique index, so concurrent writers cannot pass the read-time validator.

## Idempotency, concurrency, audit, and transaction

The idempotency receipt is stored in shared Operations with owner `identity`
and kind `identity.organization_unit_delivery`, keyed by Workspace and
idempotency key. Its request fingerprint includes the normalized request, actor, and
application audience but never the access token. Reusing a key with another
payload fails. Replay re-authorizes the current actor and persisted parent and
verifies the canonical node plus its state fingerprint; it cannot act as an
authorization or stale-state oracle.

Delivery owner, version, and canonical state fingerprint live directly on the
real `_identity_organization_units` aggregate; there is no duplicate state
table. Canonical node insert, state evidence,
idempotency receipt, and `identity.organization_unit_delivery.create` audit
event share the Identity/host Action transaction. Host rollback removes all
four effects. External management mutation of a delivery-owned node fails
subsequent replay or versioned projection with
`backend.identity.organization_unit_external_change`.

Create acquires a no-state-change write lock on the persisted parent before
reading the idempotency receipt or deriving hierarchy facts. SQLite therefore
reserves the writer before taking a tree snapshot; MySQL and PostgreSQL lock
the parent row. The persistence boundary locks and reloads the parent again and
compares the prepared path, ancestors, and depth with that locked row before
insert. A concurrent disable or move can therefore only be observed and
re-derived, or cause a fail-closed conflict; it cannot produce a child from a
stale parent path.

Both new tables are source-owned migration evidence under the host's sole
`_schema_migrations` ledger. The Identity embedded schema contract is migration
`10`, `organization_unit_delivery`.

## Stable error contract

The public adapter returns `*identitysdk.Error`. Relevant codes are:

- invalid request or projection:
  `backend.identity.organization_unit_delivery_invalid`,
  `backend.identity.organization_unit_projection_invalid`,
  `backend.identity.organization_unit_type_invalid`
- authorization/isolation:
  `backend.identity.organization_unit_scope_denied`,
  `backend.identity.organization_unit_projection_denied`,
  `backend.identity.organization_unit_actor_invalid`,
  `identity.organization_unit_delivery_application_scope_mismatch`,
  `auth.authorization_stale`
- parent/concurrency:
  `backend.identity.organization_unit_parent_invalid`,
  `backend.identity.organization_unit_version_conflict`,
  `backend.identity.organization_unit_external_change`
- uniqueness/idempotency:
  `backend.identity.organization_unit_code_exists`,
  `backend.identity.organization_unit_name_exists`,
  `backend.idempotency_key_reused`
- availability/transaction:
  `identity.organization_unit_delivery_unavailable`,
  `backend.identity.organization_unit_delivery_unavailable`,
  `identity.organization_unit_delivery_transaction_required`,
  `backend.identity.organization_unit_transaction_required`

Wrong type, missing child, out-of-scope parent, and cross-hierarchy resolve all
collapse to `backend.identity.organization_unit_projection_denied`, preventing
the projection from becoming an organization-ID or hierarchy oracle.

## Verification map

- `organizationunit/organization_unit_delivery_test.go`
- `internal/application/identity/identity_organization_unit_delivery_scope_test.go`
- `internal/infrastructure/persistence/database/identity/identity_organization_unit_delivery_dialect_test.go`
- `internal/infrastructure/persistence/database/schema/organization_unit_delivery_migration_test.go`
- `internal/assembly/identity_organization_unit_delivery_integration_test.go`
- `internal/assembly/module/handler_delivery_test.go`
- `module/factory_test.go`
