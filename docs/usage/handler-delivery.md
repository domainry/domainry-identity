# When may a Business Handler create, update, disable, or resolve an Identity user?

## Problems solved

- Atomically delivers one Identity user, the exact manual Role set, and an optional one-to-one business-profile binding without exposing credential or session storage to project code.
- Keeps actor, Workspace, Application, authorization revision, credential creation, and session revocation inside Identity's trusted boundary.

## Business scenarios

- An employee-onboarding Operation creates a login user, assigns the approved Roles, and binds the `employee_profile` record in one idempotent delivery.
- A transfer Operation updates the canonical user and exact Role set using optimistic concurrency rather than appending another assignment blindly.
- An offboarding Operation disables the user and revokes sessions while the employee profile and historical business records remain intact.
- A business command resolves the minimal bound-identity projection before recording staff attribution or checking eligibility.

## Use when

Use Handler Delivery only when a named, authorized Business Operation must change Identity-owned user state together with a governed business effect. Use the transaction-bound binding when the Identity delivery and project record must commit or roll back as one unit.

## Do not use when

Do not use it for generic account-administration screens, bulk directory synchronization, or a customer/contact who never authenticates. Do not call Identity repositories, choose a Workspace, inject an actor Role, or handle password hashes from project code.

## How to use

Publish the exact profile binding and generated Handler capability first. Runtime injects the access token and derives Workspace, Application, actor, and authorization revision. The Handler supplies the V1 contract version, a stable idempotency key, one complete desired user mutation, the exact manual Role keys, and optionally one published profile binding. Create requires `expected_version: 0` and `login_mode: none|password`; update and disable require the current version and no login mode.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Onboard a store manager with a login and employee profile | `identity.handler_delivery.create` | In the onboarding Handler, create the employee profile and deliver the user, exact `store_manager` Role, and published profile binding under one stable idempotency key | Creating a project user table, accepting a Role from the browser, or committing the profile after a partially successful Identity call |
| Change an employee's approved Roles | `identity.handler_delivery.update` | Resolve the current bound identity, pass its version, and send the complete desired manual Role set | Treating `role_keys` as additive or retrying with a stale version until it overwrites a concurrent administrator change |
| Offboard an employee | `identity.handler_delivery.disable` | Use the current version; let Identity disable the account and revoke sessions; retain the project profile for history | Deleting the employee profile, setting an `active` flag only in the project Object, or assuming token expiry is immediate revocation |
| Attribute a business action to a staff member | `identity.handler_delivery.resolve` | Resolve the published binding and consume only the minimal canonical identity projection | Querying credentials/session tables or trusting a caller-supplied display name, Role, or organization path |

## Example

An `employee.onboard` Handler may submit this generated delivery request after validating the employee profile. The bearer is injected by Runtime and is deliberately absent:

```json
{
  "contract_version": "domainry-identity-handler-delivery-v1",
  "idempotency_key": "employee.onboard:employee-1042",
  "user": {
    "operation": "create",
    "user": {
      "id": "user-1042",
      "name": "Lin Qiao",
      "email": "lin.qiao@example.test",
      "account_type": "human",
      "org_id": "store-shanghai-01",
      "status": "active",
      "version": 0
    },
    "expected_version": 0,
    "login_mode": "password"
  },
  "role_keys": ["store_manager"],
  "profile_binding": {
    "binding_key": "employee_profile",
    "object_key": "employee_profile",
    "profile_id": "employee-1042",
    "expected_version": 0,
    "reason": "approved employee onboarding"
  }
}
```

Repeating the same request and idempotency key returns a replayed result rather than a second user. If Role validation or profile binding fails, the delivery must not leave a partially assigned user. A disable result reports revoked-session count; the initial password, when created, is no-store and must never be logged or persisted.

## Permissions and scope

Create, update, disable, and resolve are four independent exact permissions. The caller must be a real authorized Service Actor in the same Workspace and registered Application scope; no request field may select another actor, Role authority, or Workspace.

## Boundaries

Identity owns credentials, sessions, canonical user status, Role assignments, and binding integrity. The project owns business-profile facts. Handler Delivery does not create arbitrary Roles, expose credentials, erase historical profiles, or replace normal Identity administration.
