import { describe, expect, it } from 'vitest'
import type { RuntimeObjectSchema } from '@/data/api'
import { isMetadataRelationTarget, metadataRelationDiagnostics, metadataRelations } from './metadata-er-diagram'

const profile: RuntimeObjectSchema = {
  key: 'employee_profile',
  fields: [{ key: 'identity_user', type: 'relation', required: true, unique: true, config: { object_key: 'identity_user', cardinality: 'one_to_one' } }],
}

describe('metadata ER relation targets', () => {
  it('accepts Runtime identity_user as a built-in relation target', () => {
    expect(isMetadataRelationTarget([profile], 'identity_user')).toBe(true)
    expect(metadataRelationDiagnostics([profile])).toEqual([])
    expect(metadataRelations([profile])).toEqual([expect.objectContaining({ source: 'employee_profile', target: 'identity_user' })])
  })

  it('continues to reject unknown domain relation targets', () => {
    const invalid: RuntimeObjectSchema = { key: 'invoice', fields: [{ key: 'customer', type: 'relation', config: { object_key: 'missing_customer' } }] }
    expect(isMetadataRelationTarget([invalid], 'missing_customer')).toBe(false)
    expect(metadataRelationDiagnostics([invalid])).toEqual([expect.objectContaining({ code: 'unknownTarget', target: 'missing_customer' })])
  })
})
