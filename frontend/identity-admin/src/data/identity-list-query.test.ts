import { describe, expect, it } from 'vitest'
import { identityListParams } from './identity-list-query'

describe('identityListParams', () => {
  it('serializes every governed list capability', () => {
    const params = new URLSearchParams(identityListParams({
      page: 2,
      pageSize: 25,
      search: '  alice  ',
      searchFields: ['name', 'email'],
      filters: { status: 'active' },
      sort: [{ field: 'name', direction: 'desc' }],
    }))
    expect(Object.fromEntries(params)).toEqual({
      page: '2',
      page_size: '25',
      search: 'alice',
      search_fields: 'name,email',
      filters: '{"status":"active"}',
      sort: 'name:desc',
    })
  })

  it('omits empty optional values', () => {
    expect(identityListParams({
      page: 1,
      pageSize: 20,
      search: ' ',
      searchFields: [],
      filters: {},
      sort: [],
    })).toBe('page=1&page_size=20')
  })
})
