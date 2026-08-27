import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const page = readFileSync(new URL('./change-password-page.tsx', import.meta.url), 'utf8')
const router = readFileSync(new URL('../../router.tsx', import.meta.url), 'utf8')
const auth = readFileSync(new URL('../../lib/auth.tsx', import.meta.url), 'utf8')

describe('temporary-password handoff contract', () => {
  it('uses the shared component library and stays outside the management shell', () => {
    expect(page).toContain("from '@domainry/ui'")
    expect(page).toContain('<Card')
    expect(page).toContain('<FieldGroup')
    expect(page).not.toContain('AdminShell')
  })

  it('mounts one Admin checkpoint and blocks shell navigation queries', () => {
    expect(router).toContain("path: '/admin/change-password'")
    expect(router.match(/path: '\/admin\/change-password'/g)).toHaveLength(1)
    expect(router).toContain('if (session.mustChangePassword)')
    expect(router).toContain('const canLoadNavigation = Boolean(session && !session.mustChangePassword)')
  })

  it('replaces the persisted session only from the backend reissue response', () => {
    expect(auth).toContain('await changeRuntimePassword(')
    expect(auth).toContain('await fetchRuntimeMe(response.access_token)')
    expect(auth).toContain('next.mustChangePassword = me.must_change_password === true')
    expect(auth).toContain('persistSession(next)')
  })
})
