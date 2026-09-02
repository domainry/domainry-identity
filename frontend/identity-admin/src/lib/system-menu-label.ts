import type { MessageKey, Translate } from '@/lib/i18n'

/**
 * Runtime menu keys are stable identities. Only platform-owned menu keys are
 * translated here; user-created menu labels remain exactly as authored.
 */
const SYSTEM_MENU_LABEL_KEYS: Readonly<Record<string, MessageKey>> = {
  org_access: 'nav.group.org',
  org_users: 'nav.users',
  org_organization_units: 'nav.organizationUnits',
  org_roles: 'nav.roles',
  org_menus: 'nav.menus',
  org_data_scopes: 'nav.dataScopes',
  org_field_permissions: 'nav.fieldPerms',
  system: 'nav.group.system',
  system_metadata: 'nav.metadata',
  system_audit: 'nav.audit',
}

export function systemMenuLabel(t: Translate, key: string, fallback: string) {
  const messageKey = SYSTEM_MENU_LABEL_KEYS[key]
  return messageKey ? t(messageKey) : fallback
}
