import { expect, test, type Page } from '@playwright/test'

const user = { id: 'metadata-author', name: 'Metadata author', email: 'metadata@example.com', status: 'active' }
const roles = [{ id: 'metadata-author', key: 'metadata-author', label: 'Metadata author' }]
const permissions = ['metadata.read', 'metadata.write']

const schema = {
  name: 'Metadata acceptance',
  template_id: 'metadata-acceptance',
  template_version: '1.0.0',
  schema_hash: 'schema-hash-v1',
  objects: [
    {
      key: 'customer',
      name: 'Customer',
      fields: [
        { key: 'name', name: 'Name', type: 'text', required: true },
        { key: 'status', name: 'Status', type: 'text' },
        {
          key: 'primary_contact',
          name: 'Primary contact',
          type: 'relation',
          validation: { target: 'contact' },
          config: { target: 'contact', cardinality: 'one_to_one', on_delete: 'restrict', inverse_name: 'primary_customer', indexed: true },
          unique: true,
        },
      ],
    },
    {
      key: 'contact',
      name: 'Contact',
      fields: [
        { key: 'name', name: 'Name', type: 'text', required: true },
      ],
    },
  ],
  actions: [],
  views: [],
  reports: [],
  workflows: [],
  menus: [],
}

async function installMetadataRuntime(page: Page, allowed = true) {
  let savedDraft: Record<string, unknown> | undefined
  const savedPlans: Array<Record<string, unknown>> = []
  const metadataRequests: string[] = []

  await page.addInitScript(({ user, roles }) => {
    localStorage.setItem('identity-admin-runtime-session', JSON.stringify({
      username: 'metadata@example.com',
      displayName: 'Metadata author',
      loginAt: new Date().toISOString(),
      roleId: 'metadata-author',
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      remember: true,
      user,
      roles,
      permissions: [],

    }))
  }, { user, roles })

  await page.route('**/api/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname.replace(/^\/api/, '')
    if (['/tenant-admin/runtime-schema', '/tenant-admin/metadata/migration-plan', '/tenant-admin/platform-capabilities'].includes(path)) metadataRequests.push(path)

    if (path === '/auth/me') return route.fulfill({ json: { user, default_role: 'metadata-author', roles, permissions: [] } })
    if (path === '/browser/auth/refresh') return route.fulfill({ json: {
      session_id: 'metadata-session', workspace_id: 'default', access_token: 'metadata-token',
      token_type: 'Bearer', expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      user, default_role: 'metadata-author', roles, permissions: [], must_change_password: false,
    } })
    if (path === '/browser/auth/logout') return route.fulfill({ status: 204 })
    if (path === '/permissions/effective') return route.fulfill({ json: {
      role_key: 'metadata-author',
      function_permissions: allowed ? permissions.map((key) => ({ key, decision: { allowed: true } })) : [],
      objects: [],
      actions: [],
    } })
    if (path === '/identity/effective-menus') return route.fulfill({ json: allowed ? [{ key: 'system_metadata', route: '/admin/system/metadata' }] : [] })
    if (path === '/tenant-admin/runtime-schema') return route.fulfill({ json: schema })
    if (path === '/tenant-admin/metadata/migration-plan') return route.fulfill({ json: { count: 0, steps: [] } })
    if (path === '/tenant-admin/platform-capabilities') return route.fulfill({ json: {
      contract_version: 'runtime-authoring-v1',
      runtime_version: 'runtime-v1',
      contract_hash: 'authoring-hash',
      domains: [{
        key: 'schema',
        capabilities: [
          { key: 'schema.field', status: 'supported', lifecycle: 'versioned_metadata', parameters: [{ key: 'type', type: 'string', enum: ['text', 'relation', 'formula'] }] },
          { key: 'schema.relation', status: 'supported', lifecycle: 'versioned_metadata', parameters: [
            { key: 'cardinality', type: 'string', enum: ['many_to_one', 'one_to_one'], default: 'many_to_one' },
            { key: 'on_delete', type: 'string', enum: ['restrict', 'set_null', 'cascade'], default: 'restrict' },
          ] },
        ],
      }],
      instance: { object_keys: ['customer', 'contact'], action_keys: [], workflow_keys: [], report_keys: [], connector_operations: [] },
    } })
    if (path === '/tenant-admin/metadata/objects/customer/record-count') return route.fulfill({ json: { object_key: 'customer', count: 2 } })
    if (path === '/tenant-admin/metadata/objects/contact/record-count') return route.fulfill({ json: { object_key: 'contact', count: 0 } })
    if (path.startsWith('/tenant-admin/metadata/definitions/field/')) {
      const key = decodeURIComponent(path.split('/').pop() ?? '')
      const [objectKey, fieldKey] = key.split('.')
      const field = schema.objects.find((object) => object.key === objectKey)?.fields.find((candidate) => candidate.key === fieldKey)
      return route.fulfill({ status: field ? 200 : 404, json: field ? { definition: { payload: field, schema_hash: `${key}-hash` } } : { code: 'backend.metadata.definition_not_found' } })
    }
    if (path === '/domain-system-snapshot') return route.fulfill({ json: {
      snapshot_hash: 'snapshot-hash',
      runtime_version: 'runtime-v1',
      authoring_contract_version: 'runtime-authoring-v1',
      authoring_contract_hash: 'authoring-hash',
      resource_sources: [
        { resource_type: 'field', resource_key: 'customer.status', source_kind: 'manual', schema_hash: 'customer.status-hash' },
      ],
    } })
    if (path === '/domain-reference-graph') return route.fulfill({ json: { version: 'v1', hash: 'graph-hash', nodes: [], edges: [] } })
    if (path === '/tenant-admin/change-plans/validate') return route.fulfill({ json: {
      valid: false,
      apply_allowed: false,
      issues: [{ field_path: 'reviewed', code: 'backend.change_plan.review_required', severity: 'error' }],
      diffs: [],
      risk_summary: {},
    } })
    if (path.startsWith('/tenant-admin/change-plans/') && request.method() === 'PUT') {
      const body = request.postDataJSON() as { plan: Record<string, unknown> }
      savedPlans.push(body.plan)
      savedDraft = {
        workspace_id: 'workspace',
        plan_id: body.plan.plan_id,
        revision: 1,
        status: 'draft',
        payload: body.plan,
        created_by: user.id,
        updated_by: user.id,
        created_at: '2026-07-26T00:00:00Z',
        updated_at: '2026-07-26T00:00:00Z',
      }
      return route.fulfill({ json: savedDraft })
    }
    if (path.startsWith('/tenant-admin/change-plans/') && request.method() === 'GET' && savedDraft) return route.fulfill({ json: savedDraft })
    return route.fulfill({ json: {} })
  })

  return { metadataRequests, savedPlans }
}

test('renders the published Runtime Schema and ER evidence at every supported breakpoint', async ({ page }, testInfo) => {
  await installMetadataRuntime(page)
  for (const viewport of [
    { name: 'mobile', width: 390, height: 844 },
    { name: 'tablet', width: 768, height: 900 },
    { name: 'desktop', width: 1280, height: 900 },
    { name: 'wide', width: 1440, height: 900 },
  ]) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height })
    await page.goto('/admin/system/metadata?resource_type=object&resource_key=customer')
    await page.getByRole('radio', { name: 'ER 关系图', exact: true }).click()
    const diagram = page.getByTestId('metadata-er-diagram')
    await expect(diagram.locator('.react-flow__node')).toHaveCount(2)
    await expect(diagram.locator('.react-flow__edge')).toHaveCount(1)
    const layout = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      tableScrollers: [...document.querySelectorAll('table')].map((table) => ({ width: table.parentElement?.clientWidth ?? 0, content: table.scrollWidth, overflowX: table.parentElement ? getComputedStyle(table.parentElement).overflowX : '' })),
    }))
    expect(layout.overflow).toBe(0)
    await page.screenshot({ path: testInfo.outputPath(`metadata-${viewport.name}.png`), fullPage: true })
  }
})

test('focuses object and field deep links and distinguishes filtered empty from backend empty', async ({ page }) => {
  await installMetadataRuntime(page)
  await page.goto('/admin/system/metadata?resource_type=field&resource_key=customer.primary_contact')
  await expect(page.getByRole('row', { name: 'Primary contact primary_contact relation contact · one_to_one · restrict — — 编辑字段Primary contact 操作' })).toHaveAttribute('aria-current', 'true')
  await expect(page.getByText('contact · one_to_one · restrict', { exact: true })).toBeVisible()
  await page.getByRole('textbox', { name: '搜索对象…' }).fill('missing')
  await expect(page.getByText('没有对象匹配当前搜索条件。', { exact: true })).toBeVisible()
  await page.goto('/admin/system/metadata?resource_type=field&resource_key=customer.missing')
  await expect(page.getByText('元数据目标不存在', { exact: true })).toBeVisible()
})

test('saves create and delete as governed drafts while the published Schema remains unchanged', async ({ page }) => {
  const runtime = await installMetadataRuntime(page)
  await page.goto('/admin/system/metadata?resource_type=object&resource_key=customer')
  await expect(page.getByTestId('metadata-field-type-compatibility-gap')).toHaveCount(0)
  await page.getByRole('button', { name: '新增字段', exact: true }).click()
  const createDialog = page.getByRole('dialog')
  await expect(createDialog.getByText('前端兼容缺口', { exact: true })).toBeVisible()
  await createDialog.getByLabel('字段编码', { exact: true }).fill('account_owner')
  await createDialog.getByLabel('字段名称', { exact: true }).fill('Account owner')
  await createDialog.getByTestId('metadata-field-type').click()
  await page.getByRole('option', { name: 'relation', exact: true }).click()
  await createDialog.getByTestId('metadata-relation-target').click()
  await page.getByRole('option', { name: 'Contact · contact', exact: true }).click()
  await createDialog.getByLabel('业务原因', { exact: true }).fill('Add an explicit account owner relationship for acceptance')
  await createDialog.getByRole('button', { name: '保存治理草稿', exact: true }).click()
  await expect(createDialog).toBeHidden()
  await expect(page.getByText('已发布 Schema 尚未改变', { exact: true })).toBeVisible()
  await expect(page.getByText('account_owner', { exact: true })).toHaveCount(0)
  expect(runtime.savedPlans).toHaveLength(1)
  expect(runtime.savedPlans[0]).toMatchObject({
    business_reason: 'Add an explicit account owner relationship for acceptance',
    items: [{ operation: 'create', resource_type: 'field', resource_key: 'customer.account_owner', capability_key: 'schema.relation' }],
  })

  const statusRow = page.getByRole('row').filter({ hasText: 'Statusstatus' })
  await expect(statusRow).toHaveCount(1)
  await statusRow.getByRole('button', { name: '操作', exact: true }).click()
  await page.getByRole('menuitem', { name: '删除', exact: true }).click()
  const deleteDialog = page.getByRole('alertdialog')
  await expect(deleteDialog.getByRole('button', { name: '保存删除草稿', exact: true })).toBeDisabled()
  await deleteDialog.getByLabel('业务原因', { exact: true }).fill('Remove deprecated status after consumer migration')
  await deleteDialog.getByRole('button', { name: '保存删除草稿', exact: true }).click()
  await expect(deleteDialog).toBeHidden()
  await expect(page.getByText('Status', { exact: true })).toBeVisible()
  expect(runtime.savedPlans).toHaveLength(2)
  expect(runtime.savedPlans[1]).toMatchObject({
    business_reason: 'Remove deprecated status after consumer migration',
    items: [{ operation: 'delete', resource_type: 'field', resource_key: 'customer.status', risk_level: 'critical' }],
  })
})

test('renders backend permission denial without querying metadata resources', async ({ page }) => {
  const runtime = await installMetadataRuntime(page, false)
  await page.goto('/admin/system/metadata')
  await expect(page.getByText('后端未授予查看 Runtime 元数据的权限。', { exact: true })).toBeVisible()
  expect(runtime.metadataRequests).toEqual([])
})
