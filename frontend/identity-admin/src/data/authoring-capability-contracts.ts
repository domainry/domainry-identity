export interface RuntimeAuthoringCapabilityContract {
  contract_version: string
  runtime_version: string
  contract_hash: string
  instance_hash?: string
  domains: RuntimeAuthoringCapabilityDomain[]
  instance: RuntimeAuthoringInstanceCapabilities
}

export interface RuntimeAuthoringCapabilityDomain {
  key: string
  capabilities: RuntimeAuthoringCapability[]
}

export interface RuntimeAuthoringCapability {
  key: string
  status: string
  lifecycle: string
  allowed_contexts?: string[]
  parameters?: RuntimeAuthoringCapabilityParameter[]
  requires?: string[]
  conflicts?: string[]
  permissions?: string[]
  audit_events?: string[]
  validation_endpoint?: string
  preview_endpoint?: string
  simulation_endpoint?: string
  configuration_routes?: string[]
  resource_operations?: RuntimeAuthoringResourceOperations
  resource_key_path_parameter?: string
  errors?: RuntimeAuthoringError[]
  examples?: RuntimeAuthoringExample[]
  input_schema?: RuntimeAuthoringSchema
  output_schema?: RuntimeAuthoringSchema
  output_variables?: RuntimeAuthoringOutput[]
  reference_contracts?: RuntimeAuthoringReference[]
  execution?: RuntimeAuthoringExecution
  sources?: Array<{ kind: string; path: string; symbol?: string }>
}

export interface RuntimeAuthoringCapabilityParameter {
  key: string
  type: string
  required?: boolean
  default?: unknown
  enum?: string[]
  minimum?: number
  maximum?: number
  min_length?: number
  max_length?: number
  required_when?: Record<string, unknown>
  conflicts_with?: string[]
  item_schema?: string
  format?: string
  read_only?: boolean
}

export interface RuntimeAuthoringSchema {
  $schema?: string
  $ref?: string
  type?: string
  properties?: Record<string, RuntimeAuthoringSchema>
  $defs?: Record<string, RuntimeAuthoringSchema>
  required?: string[]
  items?: RuntimeAuthoringSchema
  oneOf?: RuntimeAuthoringSchema[]
  enum?: unknown[]
  const?: unknown
  default?: unknown
  format?: string
  minimum?: number
  maximum?: number
  minLength?: number
  maxLength?: number
  minItems?: number
  maxItems?: number
  additionalProperties?: boolean
  description?: string
}

export interface RuntimeAuthoringResourceOperations {
  persistence_mode: string
  validate: string
  upsert: string
  upsert_headers?: Array<{ name: string; required: boolean; value_source: string; description: string }>
  success_schema?: RuntimeAuthoringSchema
  get: string
  versions: string
  simulate?: string
  rollback?: string
  delete?: string
}

export interface RuntimeAuthoringError {
  code: string
  field_path?: string
  parameter_keys?: string[]
  message_key: string
}

export interface RuntimeAuthoringExample {
  name: string
  value: Record<string, unknown>
  expected_error_codes?: string[]
}

export interface RuntimeAuthoringOutput {
  name: string
  json_pointer: string
  type: string
  visible_to: string
}

export interface RuntimeAuthoringReference {
  kind: string
  input_json_pointer: string
  scope_from?: string
  resolver_endpoint: string
}

export interface RuntimeAuthoringExecution {
  read_set?: string[]
  write_set?: string[]
  boundary_class?: string
  transaction: string
  idempotency: string
  side_effects?: string[]
  side_effect_level: string
  compensation?: string
  permission_model: string
  change_control?: string
}

export interface RuntimeAuthoringInstanceCapabilities {
  object_keys: string[]
  field_keys?: Array<{ scope: string; values: string[] }>
  action_keys: string[]
  role_keys?: string[]
  permission_keys?: string[]
  user_ids?: string[]
  department_ids?: string[]
  role_ids?: string[]
  menu_ids?: string[]
}

export function authoringParameter(
  contract: RuntimeAuthoringCapabilityContract,
  capabilityKey: string,
  parameterKey: string,
) {
  return contract.domains
    .flatMap((domain) => domain.capabilities)
    .find((capability) => capability.key === capabilityKey)
    ?.parameters?.find((parameter) => parameter.key === parameterKey)
}

export function authoringEnumValues(
  contract: RuntimeAuthoringCapabilityContract,
  capabilityKey: string,
  parameterKey: string,
) {
  return authoringParameter(contract, capabilityKey, parameterKey)?.enum ?? []
}

export function authoringNumberBounds(
  contract: RuntimeAuthoringCapabilityContract,
  capabilityKey: string,
  parameterKey: string,
) {
  const parameter = authoringParameter(contract, capabilityKey, parameterKey)
  return { minimum: parameter?.minimum, maximum: parameter?.maximum, default: parameter?.default }
}
