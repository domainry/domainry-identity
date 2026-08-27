# Identity Frontend Shared Packages

This directory contains the two shared packages used by `identity-admin`.

- `ui`: shadcn/Radix primitives, shared tokens, and low-level UI helpers.
- `surface-contract`: typed contracts for the Identity Admin surface and audience.

Identity-specific pages and orchestration stay in `frontend/identity-admin`.

App code should import shared primitives from `@domainry/ui` instead of
`@/components/ui/*`. The old `identity-admin/src/components/ui` copy has been
removed from the workspace app; new shadcn primitives should be added from
`frontend/packages/ui`.
