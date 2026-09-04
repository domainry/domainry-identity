import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
const accounts = readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8')
const assignments = readFileSync(new URL('./identity-role-assignment-list.tsx', import.meta.url), 'utf8')
const hooks = readFileSync(new URL('../../data/hooks.ts', import.meta.url), 'utf8')

describe('governed directories use server list queries', () => {
  it('uses paged Runtime endpoints for account and role assignment lists', () => {
    for (const endpoint of [
      '/identity/users/search?',
      '/role-assignments/search?',
    ]) {
      expect(api).toContain(endpoint)
    }
    expect(accounts).toContain('useIdentityAccountsPage')
    expect(assignments).toContain('useIdentityRoleAssignmentsPage')
  })

  it('sends search, filter, sort, and pagination state instead of filtering returned rows', () => {
    for (const source of [accounts, assignments]) {
      expect(source).toContain('searchFields:')
      expect(source).toContain('filters:')
      expect(source).toContain('sort:')
      expect(source).toContain('manualPagination=')
      expect(source).toContain('isRefreshing=')
      expect(source).not.toContain('.filter((profile)')
      expect(source).not.toContain('.filter((account)')
    }
    expect(hooks.match(/placeholderData: \(previous\) => previous/g)).toHaveLength(3)
  })

  it('loads the user projection without per-user role and security requests', () => {
    const start = api.indexOf('export const usersApi')
    const list = api.slice(start, api.indexOf('  async get(', start))
    expect(list).toContain('/identity/accounts/search?')
    expect(list).toContain('entry.roles.map')
    expect(list).toContain('entry.security.last_login_at')
    expect(list).toContain('entry.identity_badges')
    expect(list).not.toContain('userRoleAssignments(')
    expect(list).not.toContain('/security')
    expect(list).not.toContain('Promise.all')
  })
})
