export type MetadataFieldControl = 'key' | 'name' | 'type' | 'required' | 'defaultValue' | 'targetObject' | 'cardinality' | 'onDelete' | 'inverseName' | 'indexed'

export function metadataFieldControl(fieldPath: string): MetadataFieldControl | undefined {
  const normalized = fieldPath.replace(/^payload\./, '').replace(/^field\./, '')
  if (normalized.endsWith('key')) return 'key'
  if (normalized.endsWith('name')) return 'name'
  if (normalized.endsWith('type')) return 'type'
  if (normalized.endsWith('required')) return 'required'
  if (normalized.endsWith('default') || normalized.endsWith('default_value')) return 'defaultValue'
  if (normalized.includes('target')) return 'targetObject'
  if (normalized.endsWith('cardinality')) return 'cardinality'
  if (normalized.endsWith('on_delete')) return 'onDelete'
  if (normalized.endsWith('inverse_name')) return 'inverseName'
  if (normalized.endsWith('indexed')) return 'indexed'
  return undefined
}
