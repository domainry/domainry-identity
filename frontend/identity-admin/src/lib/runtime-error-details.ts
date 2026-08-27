import type { RuntimeApiError } from './runtime-api'
import type { Translate } from './i18n'

const constraintLabels = ['allowed', 'minimum', 'maximum', 'expected', 'expected_type', 'actual'] as const

export type RuntimeErrorBusinessKind = 'permission' | 'read_only' | 'data_scope' | 'validation'

export function runtimeErrorBusinessKind(error: RuntimeApiError | undefined): RuntimeErrorBusinessKind {
  if (!error) return 'validation'
  const code = error.code
  if (/(outside_scope|data_denied|data_permission_denied)/.test(code)) return 'data_scope'
  if (/(owner_write_denied|read_only|immutable|field_permission|retention_guard)/.test(code)) return 'read_only'
  if (error.status === 403 || /(permission_denied|permission_required)/.test(code)) return 'permission'
  return 'validation'
}

export function runtimeErrorBusinessMessage(t: Translate, error: RuntimeApiError | undefined, fallback: string) {
  const kind = runtimeErrorBusinessKind(error)
  return kind === 'validation' ? fallback : t(`runtime.error.business.${kind}` as never)
}

export function runtimeErrorConstraintDetails(t: Translate, error: RuntimeApiError | undefined) {
  if (!error) return []
  return constraintLabels.flatMap((key) => {
    const value = error.params[key]
    return value ? [t(`runtime.error.constraint.${key}` as never, { value })] : []
  })
}

export function runtimeErrorConstraintMessage(t: Translate, error: RuntimeApiError | undefined, fallback: string) {
  const details = runtimeErrorConstraintDetails(t, error)
  const message = runtimeErrorBusinessMessage(t, error, fallback)
  return details.length ? `${message} (${details.join(' · ')})` : message
}
