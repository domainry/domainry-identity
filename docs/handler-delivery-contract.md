# Identity HandlerDelivery v1

`HandlerDelivery` is Identity's typed, non-HTTP capability for Runtime-generated
business handlers. It composes one canonical Identity user, the exact set of
manual role assignments, and an optional one-to-one business profile binding.
The embedded form joins the Runtime Action transaction; it never calls back to
Runtime over HTTP and generated project code never receives a database handle or
transaction executor.

Workspace is the only tenant boundary. This contract has no TenantID input,
mapping, parent-tenant aggregate, or tenant shadow. A project role named
`tenant_admin` remains only a role key inside one Workspace.

## Stable consumer surface

The public types and interfaces live in the sibling SDK:

- `identity/handler_delivery.go`: request/result types, login modes, minimal
  bound-identity projection, permission constants, and `HandlerDelivery`.
- `sdk.go`: root aliases plus `HandlerDeliveryUnitOfWorkBinder` and
  `EmbeddedHandlerDeliveryBinding` for Runtime infrastructure.

The contract version is `domainry-identity-handler-delivery-v1`.

Runtime infrastructure must perform these steps inside the already-open Action
unit of work:

1. Discover `EmbeddedHandlerDeliveryBinding` on the embedded Identity module.
2. Call `HandlerDeliveryUnitOfWorkBinder().BindHandlerDeliveryUnitOfWork(...)`
   with `EmbeddedTransaction{Executor: actionTransaction}`. The executor accepts
   a real `*sql.Tx` or domainry-orm `driver.Transaction`, including SQLite's
   immediate transaction implementation.
3. Inject only the returned `HandlerDelivery` into generated project handler
   code. Do not inject the binder, `EmbeddedTransaction`, its executor, DB, or
   the full Identity Binding.
4. Call `DeliverIdentity` or `ResolveBoundIdentity` with the trusted request
   bearer injected by Runtime. Commit or roll back only at the outer Runtime
   Action boundary.

If transaction binding is unavailable or the executor is a pool, bare
connection, or another value without host transaction semantics, Runtime must
fail the Action with
`identity.handler_delivery_transaction_required`. It must not fall back to a
multi-request HTTP workflow.

## Purpose-specific authorization

The exact permission keys are:

- `identity.handler_delivery.create`
- `identity.handler_delivery.update`
- `identity.handler_delivery.disable`
- `identity.handler_delivery.resolve`

They are Identity-owned non-HTTP Actions with no public CRUD route. Each grant
retains its own canonical data scope: `all`, `org`, `org_child`, or
`target_org`. Current and destination organization facts are both checked for
updates, preventing an authorized record from being moved out of scope.

These grants do not confer `identity.users.*`,
`identity.user_role_assignments.*`, or `identity.profile_bindings.command`.
Conversely, those lower-level permissions do not authorize HandlerDelivery.
Identity still applies role audience/assignment eligibility, conflict rules,
privileged self-grant denial, and the caller's `GrantableRoleKeys` ceiling.

The caller cannot submit Workspace ID, actor ID, actor role, hierarchy, data
scope, or authorization facts. Identity derives them from the verified bearer,
the registered application audience, and persisted Identity state. A stale
authorization revision is rejected.

## Write semantics

For `create`, `ExpectedVersion` must be zero and `LoginMode` must be explicit:

- `none`: create a non-password-login business person and no credential row.
- `password`: Identity generates the random initial password, hashes it with
  bcrypt, and inserts the credential in the same host transaction. The handler
  never supplies a password or hash.

Only the first successful `password` create result carries
`InitialCredential.InitialPassword`, `MustChangePassword=true`, and
`NoStore=true`. `InitialCredential` is excluded from JSON, audit metadata, and
the durable idempotency receipt. Runtime must wait for the outer Action commit
before emitting it and must set the eventual response/cache policy to no-store.
If the transaction rolls back, Runtime discards it. If commit succeeds but the
process dies before delivery, replay intentionally does not reveal or rotate the
password; the normal password-reset/invitation flow is the recovery path.

For `update` and `disable`, `LoginMode` must be empty and `ExpectedVersion` must
equal the current Identity user version. Neither operation creates, resets, or
rehashes a credential. Disable sets the canonical user status to disabled and
revokes active refresh sessions in the same transaction.

`RoleKeys` is the complete desired set of manual roles, not an incremental
patch. Profile binding metadata chooses the trusted relation field and lifecycle
policy; project code cannot submit a SQL column. User, roles, profile relation,
session revocation, audit event, and `_identity_handler_deliveries` receipt share
the same executor.

The idempotency key is scoped by Workspace. Identity fingerprints the canonical
payload together with the server-derived actor and application audience. An
exact replay returns the persisted result with `Replayed=true`; reusing the key
with a different payload returns `backend.idempotency_key_reused`. Durable
receipts make this behavior restart-safe.

## NightPOS consumption rule

`employee_profile` should retain `identity_user_id` as its one-to-one Identity
reference plus genuinely business-owned employee fields. It should not duplicate
canonical display name, active/disabled state, role, organization, hierarchy, or
contact data.

Scheduling, clock, and order handlers must read the persisted
`employee_profile.identity_user_id` inside their Action UoW and call
`ResolveBoundIdentity`. For an Identity update/disable, the generated wrapper
also supplies its statically published binding key/object and the business
profile ID. Identity verifies that exact active binding belongs to the resolved
user and returns its current CAS version. The returned projection is deliberately limited to:

- user ID, current display name, status/active flag, and CAS version;
- primary/support organization IDs, canonical organization path/scope IDs,
  manager/reporting path, and reporting scope IDs;
- the exact active role keys.
- the one requested profile binding reference and Identity-owned CAS version,
  when a static profile selector was supplied.

It contains no email, phone, password/hash, MFA, provider, or session data.
Browser fields such as `staff_name`, `cast_name`, or `active` are display/input
candidates only and must never become attribution or eligibility authority.

## Identity-owned implementation and evidence

- `internal/application/identity/identity_handler_delivery_application_service.go`
  owns authentication, application audience checks, exact authorization,
  idempotency, CAS, role ceiling, minimal reads, and audit orchestration.
- `internal/infrastructure/persistence/database/identity/identity_handler_delivery_store.go`
  owns the single-executor aggregate write and durable receipt.
- `internal/assembly/module/handler_delivery.go` owns the infrastructure-only
  host transaction binder.
- `internal/infrastructure/persistence/database/schema/identity.go` owns the
  receipt DDL through Identity's migration contribution to the host's sole
  `_schema_migrations` ledger.
- `internal/assembly/identity_handler_delivery_integration_test.go` covers
  first/replayed/restarted credentials, same-key conflict, CAS, specialized
  permission isolation, role ceiling, minimal staff reads, no-login users,
  downstream failure rollback, session revocation, and unchanged credentials.
- `internal/infrastructure/persistence/database/identity/integrationtest/identity_handler_delivery_store_integration_test.go`
  covers atomic user/credential/role/profile/receipt rollback and commit.

The downstream failure test is the failure-injection seam: Identity completes
inside a host transaction, the simulated business handler then fails, and the
host rolls back. No user, credential, role, profile link, audit event, or receipt
survives. A later retry deterministically rebuilds the same aggregate.

## Consumer gaps outside this repository

No Runtime, Plane, or NightPOS source is changed by this delivery. Their owners
still need to:

1. Upgrade to this sibling Identity SDK and implement the Action-UoW binding and
   narrow capability injection described above.
2. Publish the four exact HandlerDelivery permissions in the NightPOS V3 role
   model with the intended per-role data scopes. Do not grant generic Identity
   CRUD as a substitute.
3. Publish the `employee_profile` Identity profile extension/binding metadata
   (`binding_key`, object key, `identity_user_id` relation, one-to-one lifecycle)
   through the existing trusted Identity metadata path. The current
   `ProjectRoleCatalog` SDK surface publishes roles/objects but does not yet carry
   profile extensions, so a typed project-profile-extension publisher remains a
   Runtime/SDK integration gap if the existing metadata path cannot supply it.
4. Remove duplicated canonical fields from the NightPOS schema and generated UI,
   and change scheduling/clock/order handlers to resolve their persisted
   `identity_user_id` through the injected minimal capability.
5. Buffer the one-time credential until Action commit, apply no-store transport
   headers, and ensure structured logs/traces never serialize it.
