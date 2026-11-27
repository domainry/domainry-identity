# When may a Business Handler create or manage an Identity organization unit?

## Problems solved

- Delivers a real principal-placement and authorization node through Identity instead of copying hierarchy into project tables.
- Prevents a Handler from forging path, ancestors, depth, status, parent scope, or cross-Application authority.

## Business scenarios

- A store-opening Operation creates a store below an authorized region, then later renames or disables that same store with optimistic concurrency.
- A setup Operation creates a region, department, team, or warehouse below a persisted parent and resolves the canonical minimal projection.
- A form needs a bounded page of stores that the current Service Actor may operate, not the entire installation directory.

## Use when

Use organization delivery when a named business command must create or manage an Identity organization unit because that node places principals or defines `org`, `org_child`, or `target_org` authorization.

## Do not use when

Do not use it for product categories, CRM customer companies, project teams with no authorization meaning, or ordinary administrator-driven organization management. Do not mirror Identity's hierarchy into a project Relation.

## How to use

Use `identity.organization_unit_delivery` for create, rename, disable, resolve,
and bounded list. Products define their own lower-snake-case node types (for
example `region`, `store`, or `department`); node type is data, not a separate
framework service class.
Create accepts any persisted active parent. The product chooses the permitted
topology in its compiled capability (for example company → region → store).
V1 does not create a company root or move an existing node.

Runtime injects the access token. The Handler supplies the published contract version, stable idempotency key, stable organization ID, current version where required, and the parent candidate allowed by the generated capability. Identity authorizes against persisted hierarchy and computes canonical path facts.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Open a store under one region | Organization Unit Delivery `create` with `node_type: "store"` | Use a stable store ID, persisted region parent, code/name, `expected_version: 0`, and an Operation-scoped idempotency key | Accepting path/ancestor values from the browser or creating a `store_org` Object as a second hierarchy |
| Rename or close an existing store | Organization Unit Delivery `rename` / `disable` | Pass the stable ID, `node_type: "store"`, and current version; Identity preserves code and parent and applies CAS | Delete-and-create, moving the store by changing a parent field, or retrying with a stale version |
| Create a region or department | Organization Unit Delivery `create` | Select an allowed child type and an authorized persisted parent; let Identity derive path, ancestors, depth, and active status | Using this V1 contract to create a root company or store, or supplying a fabricated parent path |
| Populate a store selector | Organization Unit Delivery `list` with `node_type: "store"` | Request a keyset page of at most 100 records and follow the opaque cursor | Downloading the full organization tree or filtering unauthorized nodes in the browser |

## Example

Store creation:

```json
{
  "contract_version": "domainry-identity-organization-unit-delivery-v1",
  "idempotency_key": "store.open:store-shanghai-01",
  "organization": {
    "operation": "create",
    "organization_id": "store-shanghai-01",
    "code": "SHA-01",
    "name": "Shanghai Store 01",
    "node_type": "store",
    "parent_organization_id": "region-shanghai",
    "sort_order": 10,
    "expected_version": 0
  }
}
```

For a department, use the same contract with `node_type: "department"`. V1
rejects only the root `company` type. Replaying the same create identity returns
the prior result. A forged or unauthorized parent, duplicate sibling identity,
invalid node type, stale version, or Application-scope mismatch fails without a
partial hierarchy change.

## Permissions and scope

Create, rename, disable, resolve, and list are independent exact permissions.
Identity derives the caller and Application scope from the trusted token and
checks persisted hierarchy; the request cannot grant itself a wider subtree.

## Boundaries

Identity owns hierarchy and authorization semantics. Business attributes such
as store hours, capacity, or sales targets remain in a project Object. V1 cannot
move a node or create a company root; topology and quota rules belong to the
product/runtime capability, not an Identity store-specific model.
