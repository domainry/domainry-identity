import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { metadataFieldControl } from './metadata-field-error'

describe('metadata authoring contract', () => {
  it('discovers Runtime field types while preserving dedicated UI support boundaries', () => {
    const source = readFileSync(new URL('./metadata.tsx', import.meta.url), 'utf8')
    expect(source).toContain("authoringParameter(capabilitiesQuery.data, 'schema.field', 'type')?.enum")
    expect(source).toContain('supportedFieldTypes.filter((type) => !DEVELOPED_METADATA_FIELD_TYPES.has(type))')
    expect(source).toContain('supportedFieldTypes.filter((type) => DEVELOPED_METADATA_FIELD_TYPES.has(type))')
    expect(source).toContain("data-testid='metadata-field-type-compatibility-gap'")
    expect(source).toContain('selectedTypeUnsupported')
    expect(source).toContain("businessReason: z.string().trim().min(1")
    expect(source).not.toContain('saving || unsupportedFieldTypes.length > 0')
  })

  it('waits for backend authorization and saves a governed draft instead of reloading metadata', () => {
    const page = readFileSync(new URL('./metadata.tsx', import.meta.url), 'utf8')
    const api = readFileSync(new URL('../../data/identity-system-api.ts', import.meta.url), 'utf8')
    expect(page).toContain("enabled: canRead")
	 expect(page).toContain("permissions.has('identity.metadata.manifest.get')")
	 expect(page).toContain("permissions.has('identity.metadata.definition.upsert')")
	 expect(page).toContain("permissions.has('identity.metadata.definition.disable')")
    expect(page).not.toContain('metadataApi.reload')
    expect(api).toContain('reason: businessReason.trim()')
  })

  it('maps server field paths to dedicated metadata controls', () => {
    expect(metadataFieldControl('payload.type')).toBe('type')
    expect(metadataFieldControl('validation.target')).toBe('targetObject')
    expect(metadataFieldControl('config.on_delete')).toBe('onDelete')
    expect(metadataFieldControl('field')).toBeUndefined()
  })
})
