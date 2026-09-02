import { afterEach, describe, expect, it, vi } from 'vitest'
import { rolesApi } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('role creation governance contract', () => {
  it('creates a fail-closed RoleSchema directly in Identity', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({}), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    await rolesApi.create({
      name: 'Runtime QA',
      code: 'RUNTIME_QA',
      description: 'Runtime acceptance role',
      members: 0,
      status: 'active',
      businessReason: 'Grant the QA operator only the governed acceptance capabilities.',
	  permissionKeys: ['identity.organization_units.list'],
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toContain('/identity/roles')
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(request.method).toBe('POST')
    expect(new Headers(request.headers).get('Idempotency-Key')).toBeTruthy()
    const body = JSON.parse(String(request.body))
    expect(body.business_reason).toBe('Grant the QA operator only the governed acceptance capabilities.')
    expect(body.role).toMatchObject({
      key: 'runtime_qa',
      description: 'Runtime acceptance role',
      permissions: ['identity.organization_units.list'],
      record_scope: 'none',
      data_permissions: [],
      field_permissions: [],
    })
  })
})
