import { afterEach, describe, expect, it, vi } from 'vitest'
import { RuntimeApiError, changeRuntimePassword, fetchRuntimeMe, runtimeApiError, runtimeRequest, runtimeRequestWithResponse, updateRuntimeCurrentUserLocale } from './runtime-api'
import { runtimeErrorBusinessKind, runtimeErrorConstraintMessage } from './runtime-error-details'
import { identityClient } from './identity-client'

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('RuntimeApiError', () => {
  it('preserves the complete machine-readable authoring error contract', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'backend.integration.connector.operation_method_invalid',
      message_key: 'backend.integration.connector.operation_method_invalid',
      message: 'Unsupported operation method.',
      field_path: 'operations[0].method',
      params: { allowed: 'GET,POST', actual: 'FETCH' },
      capability_key: 'integration.connector_operation',
      contract_version: 'runtime-authoring-v1',
      request_id: 'request-1',
    }), { status: 400, headers: { 'content-type': 'application/json' } })))

    let error: ReturnType<typeof runtimeApiError>
    try {
      await runtimeRequest('/test')
    } catch (value) {
      error = runtimeApiError(value)
    }
    expect(error).toMatchObject({ status: 400, code: 'backend.integration.connector.operation_method_invalid', fieldPath: 'operations[0].method', capabilityKey: 'integration.connector_operation', contractVersion: 'runtime-authoring-v1' })
    expect(error?.params).toEqual({ allowed: 'GET,POST', actual: 'FETCH' })
    expect(error?.payload.request_id).toBe('request-1')
    const t = ((key: string, params?: Record<string, string>) => `${key}:${params?.value ?? ''}`) as never
    expect(runtimeErrorConstraintMessage(t, error, error?.message ?? '')).toContain('runtime.error.constraint.allowed:GET,POST')
    expect(runtimeErrorConstraintMessage(t, error, error?.message ?? '')).toContain('runtime.error.constraint.actual:FETCH')
    expect(runtimeErrorBusinessKind(new RuntimeApiError(403, { code: 'backend.record.outside_scope' }, 'denied'))).toBe('data_scope')
    expect(runtimeErrorBusinessKind(new RuntimeApiError(403, { code: 'backend.record.owner_write_denied' }, 'denied'))).toBe('read_only')
    expect(runtimeErrorBusinessKind(new RuntimeApiError(403, { code: 'auth.permission_denied' }, 'denied'))).toBe('permission')
  })

  it('passes the caller AbortSignal to fetch', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()
    await runtimeRequest('/context-probe', { signal: controller.signal })
    expect(fetchMock.mock.calls[0]?.[1]?.signal).toBe(controller.signal)
  })

  it('routes ordinary authenticated business requests through the Identity client', async () => {
    const authorizedFetch = vi.spyOn(identityClient, 'authorizedFetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }),
    )
    await runtimeRequest('/context-probe')
    expect(authorizedFetch).toHaveBeenCalledOnce()
    expect(authorizedFetch.mock.calls[0]?.[0]).toBe('/api/context-probe')
  })

  it('returns backend-owned response metadata without changing the regular request API', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify([{ role_id: 'admin' }]), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'X-Resource-Hash': 'runtime-hash-1',
        'X-Request-ID': 'runtime-success-request',
      },
    })))
    const response = await runtimeRequestWithResponse<Array<{ role_id: string }>>('/identity/users/user-1/role-assignments')
    expect(response.data).toEqual([{ role_id: 'admin' }])
    expect(response.data).not.toHaveProperty('request_id')
    expect(response.headers.get('X-Resource-Hash')).toBe('runtime-hash-1')
    expect(response.status).toBe(200)
  })

  it('sends a caller-provided request id for end-to-end log correlation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await runtimeRequest('/context-probe', { requestId: 'debug-order-42' })
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('X-Request-ID')).toBe('debug-order-42')
    expect(headers.get('X-Domainry-Product-Surface')).toBeNull()
  })

  it('keeps authentication requests independent from frontend shell context', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await fetchRuntimeMe('token')
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('X-Domainry-Product-Surface')).toBeNull()
  })

  it('submits password change with bearer auth and idempotency evidence but no frontend shell header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      must_change_password: false,
    }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await changeRuntimePassword(
      'Temporary1!',
      'Private2!',
      'password-handoff-request',
    )
    const [, init] = fetchMock.mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(headers.get('Idempotency-Key')).toBe('password-handoff-request')
    expect(headers.get('X-Domainry-Product-Surface')).toBeNull()
    expect(JSON.parse(String(init?.body))).toEqual({
      current_password: 'Temporary1!',
      new_password: 'Private2!',
    })
  })

  it('uses the current-user locale contract without a generic identity write', async () => {
    const response = { user: { id: 'employee-1', name: 'Employee', email: 'employee@example.com', locale: 'zh-CN', version: 2, org_id: '', organization_path: '', status: 'active' }, roles: [], default_role: '', permissions: [] }
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(response), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(updateRuntimeCurrentUserLocale({ locale: 'zh_cn', expected_version: 1 }, 'locale-change-1', 'access-token')).resolves.toEqual(response)
    const [url, init] = fetchMock.mock.calls[0] ?? []
    const headers = new Headers(init?.headers)
    expect(url).toMatch(/\/auth\/me$/)
    expect(init?.method).toBe('PATCH')
    expect(headers.get('Authorization')).toBe('Bearer access-token')
    expect(headers.get('Idempotency-Key')).toBe('locale-change-1')
    expect(JSON.parse(String(init?.body))).toEqual({ locale: 'zh_cn', expected_version: 1 })
  })

  it('preserves an explicitly supplied request id header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await runtimeRequest('/context-probe', { headers: { 'X-Request-ID': 'debug-from-header' } })
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('X-Request-ID')).toBe('debug-from-header')
  })

  it('generates a request id and recovers it from an error response header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('upstream unavailable', {
      status: 503,
      headers: { 'content-type': 'text/plain', 'X-Request-ID': 'runtime-response-7' },
    }))
    vi.stubGlobal('fetch', fetchMock)
    let error: ReturnType<typeof runtimeApiError>
    try {
      await runtimeRequest('/context-probe')
    } catch (value) {
      error = runtimeApiError(value)
    }
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    expect(headers.get('X-Request-ID')).toMatch(/^web_/)
    expect(error?.requestId).toBe('runtime-response-7')
  })
})
