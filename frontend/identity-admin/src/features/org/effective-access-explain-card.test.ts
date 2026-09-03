import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const card = readFileSync(new URL('./effective-access-explain-card.tsx', import.meta.url), 'utf8')
const detail = readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8')
const api = readFileSync(new URL('../../data/governance-api.ts', import.meta.url), 'utf8')

describe('account Effective Access Explain', () => {
  it('binds the viewed account to the Runtime explain request', () => {
    expect(detail).toContain("<EffectiveAccessExplainCard userID={value.id} />")
	 expect(detail).toContain("has('identity.access.explain')")
    expect(card).toContain('user_id: userID')
    expect(card).toContain('identityAccessApi.explain')
    expect(api).toContain('"/identity/access/explain"')
  })

  it('supports functional and field explanation inputs without accepting record authorization facts', () => {
    for (const input of ['object_key:', 'action:', 'field_key:']) {
      expect(card).toContain(input)
    }
    expect(card).not.toContain('record_id:')
    expect(card).toContain("disabled={!objectKey.trim() || !action.trim()")
  })

  it('renders the recursive reason tree, decision, revision, and stable grant sources', () => {
    expect(card).toContain('<ExplainReasonNode reason={result.reason}')
    expect(card).toContain('<ExplainReasonNode key=')
    for (const field of ['reason.effect', 'reason.layer', 'reason.code', 'reason.subject', 'reason.details', 'reason.sources', 'reason.children']) {
      expect(card).toContain(field)
    }
    for (const source of ['role_key', 'permission_set_key', 'permission_set_group_key', 'assignment_source', 'binding_key']) {
      expect(card).toContain(source)
    }
    expect(card).toContain('result.allowed')
    expect(card).toContain('result.authorization_revision')
    expect(card).not.toContain('snapshot.data?.permissions')
  })
})
