import { expect, test } from '@playwright/test'

async function login(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.locator('#login-username').fill('admin')
  await page.locator('#login-password').fill('Domainry@2026')
  await page.getByRole('button', { name: /登录|sign in/i }).click()
  await expect(page).not.toHaveURL(/\/login/)
}

test('menu toolbar, tree collapse, and permanent cascade deletion work together', async ({ page, request }) => {
  const loginResponse = await request.post('/api/auth/login', {
    data: { workspace_id: 'default', login: 'admin', password: 'Domainry@2026' },
  })
  expect(loginResponse.ok()).toBeTruthy()
  const token = (await loginResponse.json()).access_token as string
  const headers = { Authorization: `Bearer ${token}` }
  const suffix = Date.now().toString(36)
  const parentID = `menu_e2e_parent_${suffix}`
  const childID = `menu_e2e_child_${suffix}`
  const parentLabel = `E2E Parent ${suffix}`
  const childLabel = `E2E Child ${suffix}`

  expect((await request.put(`/api/identity/menus/${parentID}`, {
    headers,
    data: { id: parentID, key: `e2e_parent_${suffix}`, label: parentLabel, sort_order: -1000, status: 'active' },
  })).ok()).toBeTruthy()
  expect((await request.put(`/api/identity/menus/${childID}`, {
    headers,
    data: { id: childID, key: `e2e_child_${suffix}`, label: childLabel, parent_id: parentID, route: `/e2e/${suffix}`, sort_order: -999, status: 'active' },
  })).ok()).toBeTruthy()

  await login(page)
  await page.goto('/admin/org/menus')

  const toolbar = page.getByTestId('data-table-toolbar-actions')
  await expect(toolbar.getByRole('button', { name: '新增子菜单' })).toBeVisible()
  await expect(page.getByRole('button', { name: '新增子菜单' })).toHaveCount(1)

  const treeScrollArea = page.getByTestId('sortable-tree-scroll-area')
  await expect(treeScrollArea).toBeVisible()
  expect(Math.round((await treeScrollArea.boundingBox())?.height ?? 0)).toBe(520)

  const tree = page.getByRole('tree')
  const table = page.getByRole('table')
  await expect(tree.getByText(childLabel, { exact: true })).toBeVisible()
  await expect(table.getByText(parentLabel, { exact: true })).toBeVisible()
  await expect(table.getByText(childLabel, { exact: true })).toHaveCount(0)
  await tree.getByRole('button', { name: `折叠菜单${parentLabel}` }).click()
  await expect(tree.getByText(childLabel, { exact: true })).toBeHidden()
  await tree.getByRole('button', { name: `展开菜单${parentLabel}` }).click()
  await expect(tree.getByText(childLabel, { exact: true })).toBeVisible()
  await tree.getByRole('button', { name: parentLabel, exact: true }).click()
  await expect(table.getByText(childLabel, { exact: true })).toBeVisible()
  await expect(table.getByText(parentLabel, { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: '全部菜单', exact: true }).click()

  const parentRow = page.getByRole('row').filter({ hasText: parentLabel })
  await parentRow.getByRole('button', { name: '操作' }).click()
  await page.getByRole('menuitem', { name: '删除' }).click()
  const deleteResponse = page.waitForResponse((response) =>
    response.request().method() === 'DELETE' && response.url().endsWith(`/identity/menus/${parentID}`)
  )
  await page.getByRole('button', { name: '删除', exact: true }).click()
  expect((await deleteResponse).ok()).toBeTruthy()

  await expect(page.getByText(parentLabel, { exact: true })).toHaveCount(0)
  await expect(page.getByText(childLabel, { exact: true })).toHaveCount(0)
  const menusResponse = await request.get('/api/identity/menus', { headers })
  const remaining = (await menusResponse.json()) as Array<{ id: string }>
  expect(remaining.some((menu) => menu.id === parentID || menu.id === childID)).toBeFalsy()
})
