import {
  createRuntimeRequestID,
  RuntimeApiError,
  runtimeRequest,
  runtimeRequestWithResponse,
} from '@/lib/runtime-api'
import type { MenuNode } from './types'
import type { RuntimeMenu, RuntimeObjectSchema, RuntimeSchema } from './api'

function makeID(prefix: string, source: string): string {
  const normalized = source.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')
  return `${prefix}_${normalized || crypto.randomUUID().slice(0, 8)}`
}

async function identityMenus(effective = false): Promise<RuntimeMenu[]> {
  return runtimeRequest<RuntimeMenu[]>(effective ? '/identity/effective-menus' : '/identity/menus')
}

function mapMenu(menu: RuntimeMenu): MenuNode {
  return {
    id: menu.id,
    parentId: menu.parent_id ?? null,
    name: menu.label,
    code: menu.key,
    path: menu.route ?? '',
    type: menu.route ? 'page' : 'group',
    sort: menu.sort_order,
    visible: menu.status === 'active',
  }
}

interface IdentityAuthoringResult<T> {
  resource: T
}

function authoringResource<T>(value: T | IdentityAuthoringResult<T>): T {
  if (typeof value === 'object' && value !== null && 'resource' in value) {
    return (value as IdentityAuthoringResult<T>).resource
  }
  return value as T
}

async function putIdentityMenu(
  id: string,
  body: RuntimeMenu,
  expectedResourceHash: string,
): Promise<RuntimeMenu[]> {
  const requestID = createRuntimeRequestID()
  const result = await runtimeRequest<RuntimeMenu[] | IdentityAuthoringResult<RuntimeMenu[]>>(
    `/identity/menus/${encodeURIComponent(id)}`,
    {
      method: 'PUT',
      headers: {
        'Builder-Task-ID': `tenant-admin.identity-menu.${requestID}`,
        'Idempotency-Key': requestID,
        'Expected-Schema-Hash': expectedResourceHash,
      },
      body,
    },
  )
  return authoringResource(result)
}

export const effectiveMenusApi = {
  list: () => identityMenus(true),
}

export const objectsApi = {
  schemaSnapshot: () => runtimeRequest<RuntimeSchema>('/tenant-admin/runtime-schema'),

  async schema(objectKey: string): Promise<RuntimeObjectSchema> {
    const schema = await runtimeRequest<RuntimeSchema>('/tenant-admin/runtime-schema')
    const object = schema.objects?.find((item) => item.key === objectKey)
    if (!object) throw new RuntimeApiError(404, {}, `Object schema not found: ${objectKey}`)
    return object
  },
}

export const menusApi = {
  async list(): Promise<MenuNode[]> {
    return (await identityMenus()).map(mapMenu)
  },

  async create(input: Omit<MenuNode, 'id'>): Promise<MenuNode> {
    const id = makeID('menu', input.code)
    const menus = await putIdentityMenu(id, {
      id,
      key: input.code,
      label: input.name,
      route: input.path,
      parent_id: input.parentId || undefined,
      sort_order: input.sort,
      status: input.visible ? 'active' : 'disabled',
    }, 'empty')
    return mapMenu(menus.find((item) => item.id === id)!)
  },

  async update(id: string, patch: Partial<Omit<MenuNode, 'id'>>): Promise<MenuNode> {
    const path = `/identity/menus/${encodeURIComponent(id)}`
    const current = await runtimeRequestWithResponse<RuntimeMenu>(path)
    const expectedResourceHash = current.headers.get('X-Resource-Hash')?.trim()
    if (!expectedResourceHash) {
      throw new RuntimeApiError(
        503,
        { code: 'backend.authoring.resource_projection_unavailable' },
        'Identity service did not publish the authoritative menu resource hash',
      )
    }
    const existing = current.data
    const menus = await putIdentityMenu(id, {
      ...existing,
      key: patch.code ?? existing.key,
      label: patch.name ?? existing.label,
      route: patch.path ?? existing.route,
      parent_id: patch.parentId === undefined ? existing.parent_id : patch.parentId || undefined,
      sort_order: patch.sort ?? existing.sort_order,
      status: patch.visible === undefined
        ? existing.status
        : patch.visible ? 'active' : 'disabled',
    }, expectedResourceHash)
    return mapMenu(menus.find((item) => item.id === id)!)
  },

  async remove(id: string): Promise<void> {
    await runtimeRequest(`/identity/menus/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },

  async move(id: string, parentId: string | null, orderedIds: string[]): Promise<MenuNode[]> {
    let menus = await identityMenus()
    const byID = new Map(menus.map((menu) => [menu.id, menu]))
    for (const [index, menuID] of orderedIds.entries()) {
      if (!byID.has(menuID)) continue
      const current = await runtimeRequestWithResponse<RuntimeMenu>(`/identity/menus/${encodeURIComponent(menuID)}`)
      const expectedResourceHash = current.headers.get('X-Resource-Hash')?.trim()
      if (!expectedResourceHash) {
        throw new RuntimeApiError(
          503,
          { code: 'backend.authoring.resource_projection_unavailable' },
          'Identity service did not publish the authoritative menu resource hash',
        )
      }
      menus = await putIdentityMenu(menuID, {
        ...current.data,
        parent_id: menuID === id ? parentId || undefined : current.data.parent_id,
        sort_order: (index + 1) * 10,
      }, expectedResourceHash)
      for (const updated of menus) byID.set(updated.id, updated)
    }
    return menus.map(mapMenu)
  },
}
