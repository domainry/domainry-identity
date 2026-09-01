package identitymodel

import actioncontract "github.com/domainry/domainry-foundation/action"

// Identity aliases the shared deployment-neutral Action contract. Keeping
// these names local avoids leaking a Foundation dependency through Identity's
// public module facade while preventing a second incompatible model.
type IdentityHTTPActionBinding = actioncontract.HTTPBinding
type IdentityPageActionBinding = actioncontract.PageBinding
type IdentityNonHTTPActionBinding = actioncontract.NonHTTPBinding
type IdentityPermissionDefinitionContract = actioncontract.PermissionDefinition
type IdentityActionDefinition = actioncontract.ActionDefinition
