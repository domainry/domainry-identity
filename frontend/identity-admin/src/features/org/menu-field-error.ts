import type { RuntimeApiError } from '@/lib/runtime-api'

export type MenuFieldControl = 'name' | 'code' | 'path' | 'parentId' | 'sort'

export function menuFieldControl(fieldPath: string, errorCode = ''): MenuFieldControl | undefined {
  const normalized = fieldPath.replace(/^menu\./, '')
  if (normalized === 'key' || errorCode === 'backend.identity.menu_key_exists' || errorCode === 'backend.identity.menu_id_key_required') return 'code'
  if (normalized === 'label') return 'name'
  if (normalized === 'route') return 'path'
  if (normalized === 'parent_id' || errorCode.includes('menu_parent_')) return 'parentId'
  if (normalized === 'sort_order') return 'sort'
  return undefined
}

export function menuFieldError(error: RuntimeApiError | undefined, fallback: string) {
  if (!error) return { control: undefined, message: fallback }
  return { control: menuFieldControl(error.fieldPath, error.code), message: error.message }
}
