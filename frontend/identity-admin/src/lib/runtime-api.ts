import { IdentityClientError, type IdentitySession } from '@domainry/identity-client'
import { identityClient } from './identity-client'
import type { RuntimeRole, RuntimeUser } from './runtime-session'
import { routeContractForPath } from '@/app-route-registry'
import type { RuntimeProductSurface } from '@domainry/surface-contract'

const API_BASE_URL = (import.meta.env.VITE_IDENTITY_API_URL ?? '/api').replace(/\/$/, '')

export interface RuntimeErrorPayload {
  error?: string
  message?: string
  detail?: string
  code?: string
  message_key?: string
  field_path?: string
  params?: Record<string, string>
  capability_key?: string
  contract_version?: string
  request_id?: string
  [key: string]: unknown
}

export class RuntimeApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly payload: RuntimeErrorPayload,
    message: string
  ) {
    super(message)
    this.name = 'RuntimeApiError'
  }

  get code() { return this.payload.code ?? '' }
  get messageKey() { return this.payload.message_key ?? this.payload.code ?? '' }
  get fieldPath() { return this.payload.field_path ?? '' }
  get params() { return this.payload.params ?? {} }
  get capabilityKey() { return this.payload.capability_key ?? '' }
  get contractVersion() { return this.payload.contract_version ?? '' }
  get requestId() { return this.payload.request_id ?? '' }
}

export function runtimeApiError(error: unknown): RuntimeApiError | undefined {
  if (error instanceof RuntimeApiError) return error
  if (error instanceof IdentityClientError) {
    return new RuntimeApiError(error.status, {
      ...error.payload,
      code: error.code,
    }, error.message)
  }
  return undefined
}

export interface RuntimeRequestOptions extends Omit<RequestInit, 'body'> {
  auth?: boolean
  body?: unknown
  productSurface?: RuntimeProductSurface
  surfaceContext?: boolean
  requestId?: string
  token?: string
}

export interface RuntimeResponse<T> {
  data: T
  headers: Headers
  status: number
}

const REQUEST_ID_HEADER = 'X-Request-ID'
const PRODUCT_SURFACE_HEADER = 'X-Domainry-Product-Surface'

export function currentProductSurface(): RuntimeProductSurface {
  if (typeof window === 'undefined') return 'admin_console'
  const surface = routeContractForPath(window.location.pathname)?.surface
  return surface === 'admin_console' ? surface : 'admin_console'
}

export function createRuntimeRequestID() {
  const random = typeof globalThis.crypto?.randomUUID === 'function'
    ? globalThis.crypto.randomUUID()
    : `${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`
  return `web_${random}`
}

function applyRequestID(headers: Headers, requestId?: string) {
  const resolved = requestId?.trim() || headers.get(REQUEST_ID_HEADER)?.trim() || createRuntimeRequestID()
  headers.set(REQUEST_ID_HEADER, resolved)
  return resolved
}

async function readRuntimePayload(response: Response): Promise<RuntimeErrorPayload> {
  const contentType = response.headers.get('content-type') ?? ''
  return contentType.includes('application/json')
    ? ((await response.json()) as RuntimeErrorPayload)
    : ({ detail: await response.text() } satisfies RuntimeErrorPayload)
}

function attachResponseRequestID(payload: RuntimeErrorPayload, response: Response) {
  payload.request_id ||= response.headers.get(REQUEST_ID_HEADER)?.trim() || undefined
  return payload
}

export async function runtimeRequest<T>(
  path: string,
  options: RuntimeRequestOptions = {}
): Promise<T> {
  return (await runtimeRequestWithResponse<T>(path, options)).data
}

export async function runtimeRequestWithResponse<T>(
  path: string,
  { auth = true, body, productSurface, surfaceContext = true, requestId, token, headers, ...init }: RuntimeRequestOptions = {}
): Promise<RuntimeResponse<T>> {
  const requestHeaders = new Headers(headers)
  applyRequestID(requestHeaders, requestId)
  if (surfaceContext) requestHeaders.set(PRODUCT_SURFACE_HEADER, productSurface ?? currentProductSurface())
  requestHeaders.set('Accept', 'application/json')
  if (body !== undefined) requestHeaders.set('Content-Type', 'application/json')
  if (auth && token) requestHeaders.set('Authorization', `Bearer ${token}`)

  const requestInit: RequestInit = {
    ...init,
    cache: init.cache ?? 'no-store',
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: init.credentials ?? 'include',
  }
  const url = `${API_BASE_URL}${path}`
  const response = auth && token === undefined
    ? await identityClient.authorizedFetch(url, requestInit)
    : await fetch(url, requestInit)
  if (response.status === 204) {
    return { data: undefined as T, headers: response.headers, status: response.status }
  }

  const payload = await readRuntimePayload(response)
  if (!response.ok) {
    attachResponseRequestID(payload, response)
    throw new RuntimeApiError(
      response.status,
      payload,
      payload.message ?? payload.error ?? payload.detail ?? `Runtime request failed (${response.status})`
    )
  }
  return { data: payload as T, headers: response.headers, status: response.status }
}

export async function runtimeFile(
  path: string,
  { auth = true, productSurface, surfaceContext = true, requestId, token, headers, ...init }: Omit<RuntimeRequestOptions, 'body'> = {}
): Promise<{ blob: Blob; filename?: string }> {
  const requestHeaders = new Headers(headers)
  applyRequestID(requestHeaders, requestId)
  if (surfaceContext) requestHeaders.set(PRODUCT_SURFACE_HEADER, productSurface ?? currentProductSurface())
  if (auth && token) requestHeaders.set('Authorization', `Bearer ${token}`)
  const requestInit: RequestInit = {
    ...init,
    cache: init.cache ?? 'no-store',
    headers: requestHeaders,
    credentials: init.credentials ?? 'include',
  }
  const url = `${API_BASE_URL}${path}`
  const response = auth && token === undefined
    ? await identityClient.authorizedFetch(url, requestInit)
    : await fetch(url, requestInit)
  if (!response.ok) {
    const payload = await readRuntimePayload(response)
    attachResponseRequestID(payload, response)
    throw new RuntimeApiError(
      response.status,
      payload,
      payload.message ?? payload.error ?? payload.detail ?? `Runtime request failed (${response.status})`
    )
  }
  const disposition = response.headers.get('content-disposition') ?? ''
  const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1]
  return { blob: await response.blob(), filename }
}

export type RuntimeAuthResponse = IdentitySession

export interface RuntimeAuthMeResponse {
  user: RuntimeUser
  roles: RuntimeRole[]
  default_role: string
  permissions: string[]
  must_change_password: boolean
}

export function fetchRuntimeMe(token?: string) {
  return runtimeRequest<RuntimeAuthMeResponse>('/auth/me', { token, surfaceContext: false })
}

export function changeRuntimePassword(
  currentPassword: string,
  newPassword: string,
  idempotencyKey: string,
) {
  return identityClient.changePassword(currentPassword, newPassword, idempotencyKey)
}

export interface RuntimeCurrentUserLocaleUpdate {
  locale: string
  expected_version: number
}

export function updateRuntimeCurrentUserLocale(input: RuntimeCurrentUserLocaleUpdate, idempotencyKey: string, token?: string) {
  return runtimeRequest<RuntimeAuthMeResponse>('/auth/me', {
    method: 'PATCH',
    token,
    headers: { 'Idempotency-Key': idempotencyKey },
    body: input,
  })
}
