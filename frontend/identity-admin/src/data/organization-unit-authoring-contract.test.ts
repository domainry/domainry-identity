import { afterEach, describe, expect, it, vi } from 'vitest'
import { organizationUnitsApi } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('organization-unit direct-authoring contract', () => {
  it('publishes a correlated create intent against an empty resource hash', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      resource: {
        id: 'org_east_store',
        code: 'EAST_STORE',
        name: 'East Store',
        node_type: 'store',
        sort_order: 10,
        status: 'active',
      },
      resource_hash: 'created-organization-unit-resource-hash',
    }), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    const created = await organizationUnitsApi.create({
      code: 'EAST_STORE',
      name: 'East Store',
      nodeType: 'store',
      parentId: null,
      memberCount: 0,
      sort: 10,
      status: 'active',
      remark: '',
      updatedAt: '',
    })

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('Builder-Task-ID')).toMatch(/^identity-management\.organization-unit\.web_/)
    expect(headers.get('Idempotency-Key')).toMatch(/^web_/)
    expect(headers.get('Expected-Schema-Hash')).toBe('empty')
    expect(created).toMatchObject({ id: 'org_east_store', code: 'EAST_STORE', nodeType: 'store', status: 'active' })
  })

  it('observes the backend resource hash before a correlated update', async () => {
    const existing = {
      id: 'east-store',
      code: 'EAST_STORE',
      name: 'East Store',
      node_type: 'store',
      parent_id: null,
      sort_order: 10,
      status: 'active',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(existing), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'X-Resource-Hash': 'organization-unit-resource-hash',
        },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        resource: { ...existing, parent_id: 'east-region' },
        resource_hash: 'updated-organization-unit-resource-hash',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
    vi.stubGlobal('fetch', fetchMock)

    const updated = await organizationUnitsApi.update('east-store', { parentId: 'east-region' })

    const updateHeaders = new Headers(fetchMock.mock.calls[1]?.[1]?.headers)
    expect(updateHeaders.get('Builder-Task-ID')).toMatch(/^identity-management\.organization-unit\.web_/)
    expect(updateHeaders.get('Idempotency-Key')).toMatch(/^web_/)
    expect(updateHeaders.get('Expected-Schema-Hash')).toBe('organization-unit-resource-hash')
    expect(updated).toMatchObject({ id: 'east-store', parentId: 'east-region' })
  })
})
