# When may a Business Handler create or manage an Identity organization unit?

## Problems solved

- Delivers a real principal-placement and authorization node through Identity instead of copying hierarchy into project tables.
- Prevents a Handler from forging path, ancestors, depth, status, parent scope, or cross-Application authority.

## Business scenarios

- A store-opening Operation creates a store below an authorized company, then later renames or disables that same store with optimistic concurrency.
- A setup Operation creates a region, department, team, or warehouse below a persisted parent and resolves the canonical minimal projection.
- A form needs a bounded page of stores that the current Service Actor may operate, not the entire installation directory.

## Use when

Use organization delivery when a named business command must create or manage an Identity organization unit because that node places principals or defines `org`, `org_child`, or `target_org` authorization.

## Do not use when

Do not use it for product categories, CRM customer companies, project teams with no authorization meaning, or ordinary administrator-driven organization management. Do not mirror Identity's hierarchy into a project Relation.

## How to use

Choose the narrow contract by node type and lifecycle:

- `identity.store_organization_delivery` owns store create, rename, disable, resolve, and bounded list. Create requires a persisted company parent; rename and disable preserve the parent and code.
- `identity.organization_unit_delivery` owns create and resolve for region, department, team, or warehouse. V1 does not create a company root or store and cannot rename, move, or disable a node.

Runtime injects the access token. The Handler supplies the published contract version, stable idempotency key, stable organization ID, current version where required, and the parent candidate allowed by the generated capability. Identity authorizes against persisted hierarchy and computes canonical path facts.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Open a store under one company | Store Organization Delivery `create` | Use a stable store ID, persisted company parent, code/name, `expected_version: 0`, and an Operation-scoped idempotency key | Accepting path/ancestor values from the browser or creating a generic `store_org` Object as a second hierarchy |
| Rename or close an existing store | Store Organization Delivery `rename` / `disable` | Pass the stable ID and current version; Identity preserves code and parent and applies CAS | Delete-and-create, moving the store by changing a parent field, or retrying with a stale version |
| Create a region or department | Organization Unit Delivery `create` | Select an allowed child type and an authorized persisted parent; let Identity derive path, ancestors, depth, and active status | Using this V1 contract to create a root company or store, or supplying a fabricated parent path |
| Populate a store selector | Store Organization Delivery `list` | Request a keyset page of at most 100 records and follow the opaque cursor | Downloading the full organization tree or filtering unauthorized nodes in the browser |

## Example

Store creation:

```json
{
  "contract_version": "domainry-identity-store-organization-delivery-v1",
  "idempotency_key": "store.open:store-shanghai-01",
  "organization": {
    "operation": "create",
    "organization_id": "store-shanghai-01",
    "code": "SHA-01",
    "name": "Shanghai Store 01",
    "parent_organization_id": "company-cn",
    "sort_order": 10,
    "expected_version": 0
  }
}
```

For a department, use `domainry-identity-organization-unit-delivery-v1` with `node_type: "department"`; V1 rejects `company` and `store`. Replaying the same create identity returns the prior result. A forged or unauthorized parent, duplicate sibling identity, invalid node type, stale version, or Application-scope mismatch fails without a partial hierarchy change.

## Permissions and scope

Store create/rename/disable/resolve/list and generic organization create/resolve are independent exact permissions. Identity derives the caller and Application scope from the trusted token and checks the persisted parent; the request cannot grant itself a wider subtree.

## Boundaries

Identity owns hierarchy and authorization semantics. Business attributes such as store hours, capacity, or sales targets remain in a project Object. Generic V1 cannot move, rename, disable, create a company root, or create a store; use only the exact purpose-specific contract that is disclosed.
