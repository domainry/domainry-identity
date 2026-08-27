import { afterEach, describe, expect, it, vi } from 'vitest'
import { rolesApi } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('role creation governance contract', () => {
  it('publishes the operator-provided reason in the backend change-plan payload', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        snapshot_hash: 'snapshot-1',
        runtime_version: 'runtime-1',
        authoring_contract_version: 'authoring-1',
        authoring_contract_hash: 'authoring-hash-1',
        schema: { roles: [] },
        resource_sources: [],
      }), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        version: '1',
        hash: 'graph-1',
        nodes: [],
        edges: [],
      }), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        valid: true,
        apply_allowed: true,
        issues: [],
        diffs: [],
        risk_summary: {},
      }), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        workspace_id: 'default',
        plan_id: 'identity-role-runtime_qa',
        revision: 1,
        status: 'draft',
        payload: {},
        created_by: 'runtime-operator',
        updated_by: 'runtime-operator',
        created_at: '2026-07-26T00:00:00Z',
        updated_at: '2026-07-26T00:00:00Z',
      }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await rolesApi.create({
      name: 'Runtime QA',
      code: 'RUNTIME_QA',
      description: 'Runtime acceptance role',
      members: 0,
      builtIn: false,
      status: 'active',
      perms: {},
      businessReason: 'Grant the QA operator only the governed acceptance capabilities.',
      permissionKeys: ['identity.departments.read'],
      dataPermission: {
        object_key: 'job_definition',
        scope: 'all_records',
        read: true,
        write: false,
      },
    })

    const validateRequest = JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))
    const saveRequest = JSON.parse(String(fetchMock.mock.calls[3]?.[1]?.body))
    expect(validateRequest.business_reason).toBe('Grant the QA operator only the governed acceptance capabilities.')
    expect(saveRequest.plan.business_reason).toBe('Grant the QA operator only the governed acceptance capabilities.')
    expect(saveRequest.plan.items[0].after.permissions).toEqual(['identity.departments.read'])
  })
})
