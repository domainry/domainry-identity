import { runtimeRequest } from '@/lib/runtime-api'
import type { RuntimeAuthoringCapabilityContract } from './authoring-capability-contracts'
import type { RuntimeObjectField } from './api'
import { saveSystemResourceDraft } from './action-definition-api'

export interface IdentityServiceHealth {
  status: string
  service?: string
}

export const identityServiceApi = {
  health: () => runtimeRequest<IdentityServiceHealth>('/health'),
}

export const platformCapabilitiesApi = {
  get: () => runtimeRequest<RuntimeAuthoringCapabilityContract>('/capabilities'),
}

export const metadataApi = {
  migrationPlan: () =>
    runtimeRequest<{
      count: number
      steps: Array<{
        object_key: string
        table: string
        operation: string
        description: string
      }> | null
    }>('/metadata/migration-plan').then((response) => ({
      ...response,
      steps: response.steps ?? [],
    })),

  objectRecordCount: (objectKey: string) =>
    runtimeRequest<{ object_key: string; count: number }>(
      `/metadata/objects/${encodeURIComponent(objectKey)}/record-count`,
    ),

  fieldDefinition(objectKey: string, fieldKey: string) {
    return runtimeRequest<{ definition: { payload: RuntimeObjectField; schema_hash: string } }>(
      `/metadata/definitions/field/${encodeURIComponent(`${objectKey}.${fieldKey}`)}`,
    ).then((response) => ({
      field: response.definition.payload,
      schemaHash: response.definition.schema_hash,
    }))
  },

  publishField(
    objectKey: string,
    field: RuntimeObjectField,
    businessReason: string,
    current?: RuntimeObjectField,
  ) {
    const operation = current ? 'update' : 'create'
    return saveSystemResourceDraft({
      resourceType: 'field',
      resourceKey: `${objectKey}.${field.key}`,
      current,
      after: field,
      operation,
      resourceOwner: current ? undefined : 'manual',
      capabilityKey: field.type === 'relation' ? 'schema.relation' : 'schema.field',
      riskLevel: field.type === 'relation' ? 'high' : 'medium',
      validationMethods: ['metadata.validate', 'reference_graph.validate'],
      reason: businessReason.trim(),
      planIDPrefix: 'metadata-field',
    })
  },

  deleteField(
    objectKey: string,
    current: RuntimeObjectField,
    businessReason: string,
  ) {
    return saveSystemResourceDraft({
      resourceType: 'field',
      resourceKey: `${objectKey}.${current.key}`,
      current,
      operation: 'delete',
      capabilityKey: current.type === 'relation' ? 'schema.relation' : 'schema.field',
      riskLevel: 'critical',
      validationMethods: ['metadata.validate', 'reference_graph.validate'],
      reason: businessReason.trim(),
      planIDPrefix: 'metadata-field-delete',
    })
  },
}
