import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

describe('Identity governance audit explorer contract', () => {
  it('projects backend filters and opens request-correlated evidence', () => {
    const api = readFileSync(new URL('../../data/governance-api.ts', import.meta.url), 'utf8')
    const page = readFileSync(new URL('./audit.tsx', import.meta.url), 'utf8')

    expect(api).toContain("params.set('object_key', query.resource.trim())")
    expect(api).toContain("params.set('record_id', query.recordId.trim())")
    expect(api).toContain("params.set('actor_id', query.actor.trim())")
    expect(api).toContain("params.set('event', query.event.trim())")
    expect(api).toContain("params.set('request_id', query.requestId.trim())")
    expect(api).toContain('/audit/governance/events/export?')
    expect(page).toContain("t('audit.detail.request')")
    expect(page).toContain("t('audit.detail.correlation')")
    expect(page).toContain('<JsonCodeBlock value={selectedLog.metadata}')
    expect(page).toContain("filename='before.json'")
    expect(page).toContain("filename='after.json'")
    expect(page).toContain('await auditApi.export(auditQuery)')
  })
})
