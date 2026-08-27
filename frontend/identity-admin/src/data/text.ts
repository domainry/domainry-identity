import type { MessageKey, Translate } from '@/lib/i18n'

/**
 * A display text returned by the runtime or represented by an i18n key.
 *
 * Seed data ships as `i18n:<key>` so it renders in the active locale and
 * survives language switches. User-created records store plain literals.
 */
export type TextValue = string

const PREFIX = 'i18n:'

/** Wrap an i18n key so it can be stored as data. */
export function i18nText(key: MessageKey): TextValue {
  return `${PREFIX}${String(key)}`
}

/** Resolve a stored text for display in the active locale. */
export function displayText(t: Translate, value: TextValue): string {
  return value.startsWith(PREFIX) ? t(value.slice(PREFIX.length) as MessageKey) : value
}
