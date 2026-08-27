export interface IdentityListQuery {
  page: number
  pageSize: number
  search?: string
  searchFields?: string[]
  filters?: Record<string, string>
  sort?: Array<{ field: string; direction: 'asc' | 'desc' }>
}

export interface IdentityPage<T> {
  items: T[]
  page: number
  page_size: number
  total: number
  has_next: boolean
}

export function identityListParams(query: IdentityListQuery): string {
  const params = new URLSearchParams({
    page: String(query.page),
    page_size: String(query.pageSize),
  })
  if (query.search?.trim()) params.set('search', query.search.trim())
  if (query.searchFields?.length) params.set('search_fields', query.searchFields.join(','))
  if (query.filters && Object.keys(query.filters).length) params.set('filters', JSON.stringify(query.filters))
  if (query.sort?.length) params.set('sort', query.sort.map((rule) => `${rule.field}:${rule.direction}`).join(','))
  return params.toString()
}
