import { afterEach, describe, expect, it, vi } from 'vitest'
import { menusApi } from './records-api'

afterEach(() => vi.unstubAllGlobals())

describe('menu direct-authoring contract', () => {
  it('creates against an empty hash and reads the backend authoring envelope', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      resource: [{
        id: 'menu_runtime_qa',
        key: 'runtime_qa',
        label: 'Runtime QA',
        sort_order: 10,
        status: 'active',
      }],
      resource_hash: 'menu-resource-1',
    }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const created = await menusApi.create({
      parentId: null,
      name: 'Runtime QA',
      code: 'runtime_qa',
      path: '',
      type: 'group',
      sort: 10,
      visible: true,
    })

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('Builder-Task-ID')).toMatch(/^tenant-admin\.identity-menu\.web_/)
    expect(headers.get('Idempotency-Key')).toMatch(/^web_/)
    expect(headers.get('Expected-Schema-Hash')).toBe('empty')
    expect(created).toMatchObject({ id: 'menu_runtime_qa' })
  })

  it('observes the backend resource hash before updating', async () => {
    const existing = {
      id: 'menu_runtime_qa',
      key: 'runtime_qa',
      label: 'Runtime QA',
      sort_order: 10,
      status: 'active' as const,
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(existing), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'X-Resource-Hash': 'menu-current-hash',
        },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        resource: [{ ...existing, status: 'disabled' }],
        resource_hash: 'menu-updated-hash',
      }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const updated = await menusApi.update('menu_runtime_qa', { visible: false })

    const headers = new Headers(fetchMock.mock.calls[1]?.[1]?.headers)
    expect(headers.get('Expected-Schema-Hash')).toBe('menu-current-hash')
    expect(updated.visible).toBe(false)
  })
})
