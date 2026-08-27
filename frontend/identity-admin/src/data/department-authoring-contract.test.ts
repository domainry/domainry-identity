import { afterEach, describe, expect, it, vi } from 'vitest'
import { departmentsApi } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('department direct-authoring contract', () => {
  it('publishes a correlated create intent against an empty resource hash', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      resource: {
        id: 'dept_department_one',
        name: 'Department One',
        sort_order: 10,
        status: 'active',
      },
      resource_hash: 'created-department-resource-hash',
    }), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    const created = await departmentsApi.create({
      name: 'Department One',
      parentId: null,
      leader: '',
      memberCount: 0,
      sort: 10,
      status: 'active',
      remark: '',
      updatedAt: '',
    })

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('Builder-Task-ID')).toMatch(/^tenant-admin\.identity-department\.web_/)
    expect(headers.get('Idempotency-Key')).toMatch(/^web_/)
    expect(headers.get('Expected-Schema-Hash')).toBe('empty')
    expect(created).toMatchObject({ id: 'dept_department_one', status: 'active' })
  })

  it('observes the backend resource hash before a correlated update', async () => {
    const existing = {
      id: 'department-1',
      name: 'Department One',
      parent_id: null,
      sort_order: 10,
      status: 'active',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(existing), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'X-Resource-Hash': 'department-resource-hash',
        },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        resource: { ...existing, parent_id: 'department-root' },
        resource_hash: 'updated-department-resource-hash',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
    vi.stubGlobal('fetch', fetchMock)

    const updated = await departmentsApi.update('department-1', { parentId: 'department-root' })

    const updateHeaders = new Headers(fetchMock.mock.calls[1]?.[1]?.headers)
    expect(updateHeaders.get('Builder-Task-ID')).toMatch(/^tenant-admin\.identity-department\.web_/)
    expect(updateHeaders.get('Idempotency-Key')).toMatch(/^web_/)
    expect(updateHeaders.get('Expected-Schema-Hash')).toBe('department-resource-hash')
    expect(updated).toMatchObject({ id: 'department-1', parentId: 'department-root' })
  })
})
