import { IdentityClient } from '@domainry/identity-client'

const endpoint = (import.meta.env.VITE_IDENTITY_BROWSER_API_URL ?? '/api/browser').replace(/\/$/, '')

export const identityClient = new IdentityClient({
  endpoint,
  tenantId: import.meta.env.VITE_IDENTITY_TENANT_ID,
  workspaceId: import.meta.env.VITE_IDENTITY_WORKSPACE_ID ?? 'default',
  applicationKey: import.meta.env.VITE_IDENTITY_APPLICATION_KEY ?? 'domainry-identity-admin',
})
