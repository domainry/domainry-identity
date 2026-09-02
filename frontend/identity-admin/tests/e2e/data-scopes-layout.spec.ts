import { expect, test } from '@playwright/test'

const user = { id: 'admin', name: 'Administrator', email: 'admin@example.com', org_id: 'root', organization_path: '/root', status: 'active' }
const roles = [
  { id: 'admin', key: 'admin', label: 'Admin', status: 'active', permission_keys: ['identity.role_data_scopes.list'], data_scopes: [], field_permissions: [] },
  { id: 'manager', key: 'manager', label: '部门经理', status: 'active', permission_keys: ['employee_profile.read'], data_scopes: [], field_permissions: [] },
]

async function mockDataScopeMatrix(page: import('@playwright/test').Page) {
  await page.addInitScript(({ session }) => {
    window.localStorage.setItem('identity-admin-runtime-session', JSON.stringify(session))
  }, {
    session: {
      username: user.email,
      displayName: user.name,
      loginAt: new Date().toISOString(),
      roleId: 'admin',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      remember: true,
      user,
      roles: [{ id: 'admin', key: 'admin', label: 'Admin' }],
      permissions: ['identity.role_data_scopes.list'],
    },
  })
  await page.route('**/api/**', async (route) => {
    const pathname = new URL(route.request().url()).pathname.replace(/^\/api/, '')
    let body: unknown = {}
    if (pathname === '/browser/auth/refresh') body = {
      session_id: 'data-scopes-layout-session', workspace_id: 'default', access_token: 'data-scopes-layout-token',
      token_type: 'Bearer', expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      user, roles: [{ id: 'admin', key: 'admin', label: 'Admin' }], default_role: 'admin',
      permissions: ['identity.role_data_scopes.list'], must_change_password: false,
    }
    else if (pathname === '/auth/me') body = { user, roles: [{ id: 'admin', key: 'admin', label: 'Admin' }], default_role: 'admin', permissions: ['identity.role_data_scopes.list'] }
    else if (pathname === '/identity/effective-menus') body = []
    else if (pathname === '/permissions/effective') body = { function_permissions: [], objects: [] }
    else if (pathname === '/identity/users') body = []
    else if (pathname === '/identity/roles') body = roles
    else if (pathname === '/tenant-admin/runtime-schema') body = { objects: [
      { key: 'employee_profile', label: '员工业务档案', fields: [], config: {} },
      { key: 'position', label: '职位', fields: [], config: {} },
    ] }
    else if (pathname === '/identity/permissions') body = [
      ...['create', 'read', 'update', 'delete'].flatMap((action) => ['employee_profile', 'position'].map((resource) => ({
        key: `${resource}.${action}`, label: `${resource} ${action}`, system: 'domain', resource, resource_label: resource, action, category: 'object', description: '',
      }))),
      { key: 'identity.roles.list', label: 'List roles', system: 'platform', resource: 'identity.roles', resource_label: 'Roles', action: 'list', category: 'platform', description: '' },
      { key: 'leave_request.approve', label: 'Approve', system: 'domain', resource: 'leave_request', resource_label: '请假申请', action: 'approve', category: 'workflow', description: '' },
      { key: 'task.act', label: 'Task Act', system: 'platform', resource: 'task', resource_label: 'Task', action: 'act', category: 'platform', description: '' },
    ]
    else if (pathname === '/tenant-admin/platform-capabilities') body = {
      contract_version: 'test', runtime_version: 'test', contract_hash: 'test', instance: { object_keys: [], action_keys: [], workflow_keys: [], report_keys: [], connector_operations: [] },
      domains: [{ key: 'identity', capabilities: [{ key: 'identity.role_data_scope', status: 'available', lifecycle: 'stable', parameters: [{ key: 'data_scope', type: 'string', enum: ['all_records', 'department', 'owned_records', 'none'] }] }] }],
    }
    else if (/^\/identity\/roles\/[^/]+\/permissions$/.test(pathname)) {
      const roleID = pathname.split('/')[3]
      body = roleID === 'admin' ? [{ role_id: 'admin', permission_key: 'identity.role_data_scopes.list' }] : [{ role_id: 'manager', permission_key: 'employee_profile.read' }]
    } else if (/^\/identity\/roles\/[^/]+\/data-scopes$/.test(pathname)) {
      const roleID = pathname.split('/')[3]
      body = roleID === 'manager' ? [{ resource: 'employee_profile', scope: 'department' }] : []
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  })
}

test('data scope matrix keeps permissions in aligned columns', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await mockDataScopeMatrix(page)
  await page.goto('/admin/org/data-scopes')

  const table = page.getByRole('table')
  await expect(table).toBeVisible()
  await expect(table.getByRole('columnheader')).toHaveCount(8)
  for (const label of ['角色', '业务模块', '数据范围', '增', '查', '改', '删', '全选 CRUD']) {
    await expect(table.getByRole('columnheader', { name: label, exact: true })).toBeVisible()
  }
  await expect(table.getByRole('columnheader', { name: /Workspace|Approval|Task|Rule History/i })).toHaveCount(0)

  const firstDataRow = table.getByRole('row').nth(1)
  await expect(firstDataRow.getByRole('switch')).toHaveCount(4)
  await expect(firstDataRow.getByRole('combobox')).toHaveCount(1)
  await expect(firstDataRow.getByText('全局继承', { exact: true })).toBeVisible()
  await expect(firstDataRow.getByRole('switch').first()).toBeChecked()
  await expect(firstDataRow.getByRole('switch').first()).toBeDisabled()
  await expect(firstDataRow.getByRole('combobox')).toBeDisabled()
  const switchCenters = await firstDataRow.getByRole('switch').evaluateAll((switches) =>
    switches.map((item) => {
      const box = item.getBoundingClientRect()
      return box.left + box.width / 2
    })
  )
  expect(switchCenters.every((center, index) => index === 0 || center - switchCenters[index - 1] >= 60)).toBeTruthy()
})
