import { describe, expect, it } from 'vitest'

import { authoringEnumValues, authoringNumberBounds, authoringParameter, type RuntimeAuthoringCapabilityContract } from './authoring-capability-contracts'

describe('authoring capability contract', () => {
  it('reads closed values from the Runtime response instead of a frontend enum', () => {
    const contract = {
      contract_version: 'runtime-authoring-v1', runtime_version: 'runtime-capabilities-v1', contract_hash: 'hash',
      domains: [{ key: 'schema', capabilities: [{ key: 'schema.field', status: 'supported', lifecycle: 'versioned_metadata', parameters: [{ key: 'type', type: 'string', enum: ['relation', 'text'] }, { key: 'max_length', type: 'integer', minimum: 1, maximum: 200, default: 80 }] }] }],
      instance: { object_keys: [], action_keys: [] },
    } satisfies RuntimeAuthoringCapabilityContract

    expect(authoringParameter(contract, 'schema.field', 'type')?.enum).toEqual(['relation', 'text'])
    expect(authoringEnumValues(contract, 'schema.field', 'type')).toEqual(['relation', 'text'])
    expect(authoringNumberBounds(contract, 'schema.field', 'max_length')).toEqual({ minimum: 1, maximum: 200, default: 80 })
    expect(authoringParameter(contract, 'schema.field', 'unknown')).toBeUndefined()
  })
})
