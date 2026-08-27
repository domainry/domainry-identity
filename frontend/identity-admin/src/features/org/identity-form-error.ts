import type { RuntimeApiError } from '@/lib/runtime-api'

export type UserFormControl = 'name' | 'email' | 'employeeNo' | 'managerId' | 'employmentStatus' | 'deptId' | 'roleId' | 'enabled'
export type RoleFormControl = 'name' | 'code' | 'description'
export type DepartmentFormControl = 'name' | 'parentId' | 'enabled'

function identityPath(fieldPath: string) {
  return fieldPath.replace(/^(user|role|department)\./, '')
}

export function userFormControl(error: RuntimeApiError | undefined): UserFormControl | undefined {
  if (!error) return undefined
  const path = identityPath(error.fieldPath)
  if (path === 'name') return 'name'
  if (path === 'email') return 'email'
  if (path === 'employee_no') return 'employeeNo'
  if (path === 'manager_id') return 'managerId'
  if (path === 'department_id') return 'deptId'
  if (path === 'role_id') return 'roleId'
  if (path === 'status') return 'employmentStatus'
  return undefined
}

export function roleFormControl(error: RuntimeApiError | undefined): RoleFormControl | undefined {
  if (!error) return undefined
  const path = identityPath(error.fieldPath)
  if (path === 'key' || error.code === 'backend.identity.role_key_exists' || error.code === 'backend.identity.role_id_key_required') return 'code'
  if (path === 'label') return 'name'
  if (path === 'description') return 'description'
  return undefined
}

export function departmentFormControl(error: RuntimeApiError | undefined): DepartmentFormControl | undefined {
  if (!error) return undefined
  const path = identityPath(error.fieldPath)
  if (path === 'name') return 'name'
  if (path === 'parent_id' || error.code === 'backend.identity.department_parent_self' || error.code === 'backend.identity.department_cycle') return 'parentId'
  if (path === 'status') return 'enabled'
  return undefined
}
