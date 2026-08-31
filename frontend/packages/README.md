# Identity Frontend Shared Packages

This directory contains the shared packages used by `identity-admin` and its
embedded consumers.

- `management-contract`: Identity-owned management HTTP DTOs, governed list
  query serialization, and generated authoring contracts. Consumer apps may
  adapt these wire types into local view models but must not redeclare them.
- `ui`: shadcn/Radix primitives, shared tokens, and low-level UI helpers.
- `surface-contract`: typed contracts for the Identity Admin surface and audience.

Identity-specific pages and orchestration stay in `frontend/identity-admin`.

Regenerate the management authoring JSON from the repository root with
`go run ./cmd/identity-management-contracts`. The Identity contract package
test rejects drift between those artifacts and the Go owner definitions.

App code should import shared primitives from `@domainry/ui` instead of
`@/components/ui/*`. The old `identity-admin/src/components/ui` copy has been
removed from the workspace app; new shadcn primitives should be added from
`frontend/packages/ui`.
