import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query'
import {
  departmentsApi,
  auditApi,
  effectiveMenusApi,
  identityAccountsApi,
  menusApi,
  permissionsApi,
  rolesApi,
  usersApi,
  workforceApi,
  type EffectivePermissions,
  type IdentityListQuery,
  type IdentityPage,
  type RoleListQuery,
  type RolePage,
  type RoleCreateInput,
  type RuntimeRoleAssignment,
  type RuntimeMenu,
  type WorkforceLifecycleInput,
  type WorkforceOnboardingInput,
} from './api'
import type {
  Department,
  AuditLog,
  IdentityAccount,
  MenuNode,
  OrgUser,
  Role,
  WorkforceProfile,
} from './types'

export function useAuditLogs(query: { resource?: string; recordId?: string; actor?: string; event?: string; requestId?: string; createdFrom?: string; createdTo?: string } = {}): UseQueryResult<AuditLog[]> {
  return useQuery({ queryKey: [...queryKeys.audit, query], queryFn: () => auditApi.list(query) })
}

export const queryKeys = {
  departments: ['runtime', 'identity', 'departments'] as const,
  users: ['runtime', 'identity', 'users'] as const,
  workforce: ['runtime', 'identity', 'workforce'] as const,
  roles: ['runtime', 'identity', 'roles'] as const,
  menus: ['runtime', 'identity', 'menus'] as const,
  effectiveMenus: ['runtime', 'identity', 'effective-menus'] as const,
  permissions: ['runtime', 'permissions', 'effective'] as const,
  audit: ['runtime', 'audit-events'] as const,
}

type Api<T extends { id: string }, CreateInput = Omit<T, 'id'>, UpdateInput = Partial<Omit<T, 'id'>>> = {
  list(): Promise<T[]>
  create(input: CreateInput): Promise<T>
  update(id: string, patch: UpdateInput): Promise<T>
  remove(id: string): Promise<void>
}

function makeHooks<T extends { id: string }, CreateInput = Omit<T, 'id'>, UpdateInput = Partial<Omit<T, 'id'>>>(key: readonly string[], api: Api<T, CreateInput, UpdateInput>) {
  function useList(enabled = true): UseQueryResult<T[]> {
    return useQuery({ queryKey: key, queryFn: () => api.list(), enabled })
  }
  function useInvalidate() {
    const client = useQueryClient()
    return () => Promise.all([
      client.invalidateQueries({ queryKey: key }),
      client.invalidateQueries({ queryKey: queryKeys.audit }),
    ])
  }
  function useCreate(): UseMutationResult<T, Error, CreateInput> {
    const client = useQueryClient()
    const invalidate = useInvalidate()
    return useMutation({
      mutationFn: (input) => api.create(input),
      onSuccess: async (created) => {
        client.setQueryData<T[]>(key, (current) => current ? [...current.filter((item) => item.id !== created.id), created] : current)
        await invalidate()
      },
    })
  }
  function useUpdate(): UseMutationResult<T, Error, { id: string; patch: UpdateInput }> {
    const client = useQueryClient()
    const invalidate = useInvalidate()
    return useMutation({
      mutationFn: ({ id, patch }) => api.update(id, patch),
      onSuccess: async (updated) => {
        client.setQueryData<T[]>(key, (current) => current?.map((item) => item.id === updated.id ? updated : item))
        await invalidate()
      },
    })
  }
  function useRemove(): UseMutationResult<void, Error, string> {
    const client = useQueryClient()
    const invalidate = useInvalidate()
    return useMutation({
      mutationFn: (id) => api.remove(id),
      onSuccess: async (_, removedID) => {
        client.setQueryData<T[]>(key, (current) => current?.filter((item) => item.id !== removedID))
        await invalidate()
      },
    })
  }
  return { useList, useCreate, useUpdate, useRemove }
}

const departments = makeHooks<Department>(queryKeys.departments, departmentsApi)
export const useDepartments = departments.useList
export const useCreateDepartment = departments.useCreate
export const useUpdateDepartment = departments.useUpdate
export const useDeleteDepartment = departments.useRemove

const users = makeHooks<OrgUser>(queryKeys.users, usersApi)
export const useUsers = users.useList
export const useCreateUser = users.useCreate
export const useUpdateUser = users.useUpdate
export const useDeleteUser = users.useRemove

type IdentityAccountWrite = Omit<IdentityAccount, 'id' | 'version' | 'resourceHash' | 'createdAt' | 'updatedAt'>
type IdentityAccountUpdate = Partial<IdentityAccountWrite> & { expectedResourceHash?: string }
const identityAccounts = makeHooks<IdentityAccount, IdentityAccountWrite, IdentityAccountUpdate>(queryKeys.users, identityAccountsApi)
export const useIdentityAccounts = identityAccounts.useList
export function useCreateIdentityAccount() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: IdentityAccountWrite) => identityAccountsApi.provision(input),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: queryKeys.users }),
        client.invalidateQueries({ queryKey: queryKeys.audit }),
      ])
    },
  })
}
export const useUpdateIdentityAccount = identityAccounts.useUpdate
export const useDeleteIdentityAccount = identityAccounts.useRemove

export function useIdentityAccountsPage(query: IdentityListQuery): UseQueryResult<IdentityPage<IdentityAccount>> {
  return useQuery({
    queryKey: [...queryKeys.users, 'page', query],
    queryFn: () => identityAccountsApi.search(query),
    placeholderData: (previous) => previous,
  })
}

export function useWorkforceProfiles(enabled = true): UseQueryResult<WorkforceProfile[]> {
  return useQuery({ queryKey: queryKeys.workforce, queryFn: () => workforceApi.list(), enabled })
}

export function useWorkforceProfilesPage(query: IdentityListQuery, enabled = true): UseQueryResult<IdentityPage<WorkforceProfile>> {
  return useQuery({
    queryKey: [...queryKeys.workforce, 'page', query],
    queryFn: () => workforceApi.search(query),
    enabled,
    placeholderData: (previous) => previous,
  })
}

export function useIdentityRoleAssignmentsPage(userID: string, query: IdentityListQuery): UseQueryResult<IdentityPage<RuntimeRoleAssignment>> {
  return useQuery({
    queryKey: [...queryKeys.users, userID, 'role-assignments', query],
    queryFn: () => identityAccountsApi.roleAssignments(userID, query),
    enabled: Boolean(userID),
    placeholderData: (previous) => previous,
  })
}

export function useWorkforceDetail(profileID: string) {
  return useQuery({
    queryKey: [...queryKeys.workforce, profileID, 'detail'],
    queryFn: () => workforceApi.detail(profileID),
    enabled: Boolean(profileID),
  })
}

export function useWorkforceAssignableRoles(workforceProfileID: string, enabled = true) {
  return useQuery({
    queryKey: [...queryKeys.workforce, workforceProfileID, 'assignable-roles'],
    queryFn: () => workforceApi.assignableRoles(workforceProfileID),
    enabled: enabled && Boolean(workforceProfileID),
  })
}

export function useGrantWorkforceRole() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ identityUserID, workforceProfileID, roleID, reason }: { identityUserID: string; workforceProfileID: string; roleID: string; reason: string }) =>
      workforceApi.grantRole(identityUserID, workforceProfileID, roleID, reason),
    onSuccess: () => Promise.all([
      client.invalidateQueries({ queryKey: queryKeys.workforce }),
      client.invalidateQueries({ queryKey: queryKeys.audit }),
    ]),
  })
}

export function useWorkforceLifecycle() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: WorkforceLifecycleInput) => workforceApi.lifecycle(input),
    onSuccess: () => Promise.all([
      client.invalidateQueries({ queryKey: queryKeys.workforce }),
      client.invalidateQueries({ queryKey: queryKeys.audit }),
    ]),
  })
}

export function useOnboardWorkforce() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: WorkforceOnboardingInput) => workforceApi.onboard(input),
    onSuccess: () => Promise.all([
      client.invalidateQueries({ queryKey: queryKeys.users }),
      client.invalidateQueries({ queryKey: queryKeys.workforce }),
      client.invalidateQueries({ queryKey: queryKeys.audit }),
    ]),
  })
}

export function useTerminateWorkforce() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ profileID, effectiveAt, reason }: { profileID: string; effectiveAt: string; reason: string }) =>
	  workforceApi.terminate(profileID, { effective_at: effectiveAt, reason }),
    onSuccess: () => Promise.all([
      client.invalidateQueries({ queryKey: queryKeys.workforce }),
      client.invalidateQueries({ queryKey: queryKeys.audit }),
    ]),
  })
}

export function useIdentityAccount(userID: string): UseQueryResult<IdentityAccount> {
  return useQuery({ queryKey: [...queryKeys.users, userID], queryFn: () => identityAccountsApi.get(userID), enabled: Boolean(userID) })
}

export function useIdentityAccountSecurity(userID: string) {
  return useQuery({ queryKey: [...queryKeys.users, userID, 'security'], queryFn: () => identityAccountsApi.security(userID), enabled: Boolean(userID) })
}

export function useRoles(enabled = true): UseQueryResult<Role[]> {
  return useQuery({ queryKey: queryKeys.roles, queryFn: rolesApi.list, enabled })
}
export function useRolePage(query: RoleListQuery): UseQueryResult<RolePage> {
  return useQuery({
    queryKey: [...queryKeys.roles, 'page', query.page, query.pageSize, query.search ?? '', ...(query.searchFields ?? [])],
    queryFn: () => rolesApi.search(query),
    placeholderData: (previous) => previous,
  })
}
export function useCreateRole(): UseMutationResult<Role, Error, RoleCreateInput> {
  return useMutation({ mutationFn: rolesApi.create })
}

const menus = makeHooks<MenuNode>(queryKeys.menus, menusApi)
export const useMenus = menus.useList
export const useCreateMenu = menus.useCreate
export const useUpdateMenu = menus.useUpdate
export const useDeleteMenu = menus.useRemove
export function useMoveMenu(): UseMutationResult<MenuNode[], Error, { id: string; parentId: string | null; orderedIds: string[] }> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, parentId, orderedIds }) => menusApi.move(id, parentId, orderedIds),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.menus })
      void client.invalidateQueries({ queryKey: queryKeys.effectiveMenus })
      void client.invalidateQueries({ queryKey: queryKeys.audit })
    },
  })
}

export function useEffectiveMenus(enabled = true): UseQueryResult<RuntimeMenu[]> {
  return useQuery({
    queryKey: queryKeys.effectiveMenus,
    queryFn: () => effectiveMenusApi.list(),
    enabled,
  })
}

export function useEffectivePermissions(context?: { objectKey: string; recordID: string }, enabled = true): UseQueryResult<EffectivePermissions> {
  return useQuery({
    queryKey: [...queryKeys.permissions, context?.objectKey ?? '', context?.recordID ?? ''],
    queryFn: () => permissionsApi.effective(context),
    enabled,
  })
}
