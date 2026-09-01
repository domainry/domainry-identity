import type { TextValue } from './text'

/* ------------------------------------------------------------------ */
/* Shared                                                              */
/* ------------------------------------------------------------------ */

export type EntityStatus = 'active' | 'disabled'

/* ------------------------------------------------------------------ */
/* Org                                                                 */
/* ------------------------------------------------------------------ */

export interface Department {
  id: string
  parentId: string | null
  name: TextValue
  leader: TextValue
  memberCount: number
  sort: number
  status: EntityStatus
  updatedAt: string
  remark?: TextValue
}

export interface OrgUser {
  id: string
  name: TextValue
  email: string
  /** References Department.id — joined at render time. */
  deptId: string
  employeeNo: string
  phone: string
  gender: 'female' | 'male' | 'non_binary' | 'unspecified' | ''
  hireDate: string
  jobTitle: string
  jobLevel: string
  managerId: string
  managerPath: string[]
  employmentType: 'contractor' | 'full_time' | 'intern' | 'part_time' | 'temporary' | ''
  employmentStatus: 'active' | 'on_leave' | 'terminated' | ''
  /** References Role.id — joined at render time. */
  roleIds: string[]
  status: EntityStatus
  lastLogin: string
  identityBadges?: Array<{ kind: 'workforce' | 'business_profile'; key: string; id: string; status: string }>
  securitySummary?: { mfaEnabled: boolean; locked: boolean; activeSessions: number }
}

export interface IdentityAccount {
  id: string
  name: TextValue
  givenName: string
  middleName: string
  familyName: string
  namePrefix: string
  nameSuffix: string
  nativeName: string
  nameLocale: string
  accountType: 'human' | 'service' | 'automation'
  locale: string
  timezone: string
  email: string
  phone: string
  status: EntityStatus
  version: number
  /** Authoritative hash observed when loading a detail; absent on list projections. */
  resourceHash?: string
  createdAt: string
  updatedAt: string
}

export interface WorkforceProfile {
  id: string
  organizationId: string
  identityUserId: string
  workerNo: string
  workerType: 'employee' | 'contractor' | 'partner_staff' | 'temporary'
  workStatus: 'pending' | 'active' | 'suspended' | 'terminated'
  startDate: string
  endDate: string
  primaryAssignmentId: string
  version: number
}

export interface WorkforceAssignment {
  id: string
  workforceProfileId: string
  organizationUnitId: string
  positionId: string
  managerWorkforceProfileId: string
  assignmentType: 'primary' | 'secondary' | 'temporary' | 'acting'
  effectiveFrom: string
  effectiveTo: string
  status: EntityStatus
  version: number
}

export interface WorkforceBusinessProfileBadge {
  bindingKey: string
  objectKey: string
  profileId: string
  status: 'unbound' | 'invited' | 'claimed' | 'active' | 'suspended' | 'unlinked'
}

export interface WorkforceDetail {
  profile: WorkforceProfile
  assignments: WorkforceAssignment[]
  account: IdentityAccount
  businessProfiles: WorkforceBusinessProfileBadge[]
}

export interface WorkforceAssignableRole {
  id: string
  key: string
  label: string
  description: string
}

export interface Role {
  id: string
  name: TextValue
  code: string
  description: TextValue
  members: number
  builtIn: boolean
  status: EntityStatus
}

export type MenuType = 'group' | 'page'

export interface MenuNode {
  id: string
  parentId: string | null
  name: TextValue
  code: string
  path: string
  type: MenuType
  sort: number
  visible: boolean
}

export type AuditAction = 'create' | 'update' | 'delete' | 'login' | 'export'
export type AuditResult = 'success' | 'failed'

export interface AuditLog {
  id: string
  time: string
  operator: TextValue
  action: AuditAction
  module: TextValue
  detail: TextValue
  ip: string
  result: AuditResult
  event: string
  resource: string
  recordId?: string
  roleKey: string
  requestId?: string
  correlationId?: string
  metadata: Record<string, unknown>
  before?: Record<string, unknown>
  after?: Record<string, unknown>
}
