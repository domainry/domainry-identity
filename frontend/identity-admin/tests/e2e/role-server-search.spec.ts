import { expect, test } from '@playwright/test'

async function login(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.locator('#login-username').fill('admin')
  await page.locator('#login-password').fill('Domainry@2026')
  await page.getByRole('button', { name: /登录|sign in/i }).click()
  await expect(page).not.toHaveURL(/\/login/)
}

test('role table uses one backend search box for role name and code', async ({ page }) => {
  await login(page)
  await page.goto('/admin/org/roles')

  const search = page.getByPlaceholder('搜索角色名称、角色编码')
  await expect(search).toBeVisible()
  await expect(page.getByText('共 3 条', { exact: true })).toHaveCount(1)

  const labelResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return url.pathname.endsWith('/identity/roles/search') && url.searchParams.get('search') === 'identity'
  })
  await search.fill('identity')
  const labelResult = await labelResponse
  expect(labelResult.ok()).toBeTruthy()
  expect(new URL(labelResult.url()).searchParams.get('search_fields')).toBe('label,key')
  await expect(page.getByText('Identity Effective', { exact: true })).toBeVisible()
  await expect(page.getByText('共 1 条', { exact: true })).toHaveCount(1)

  const keyResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return url.pathname.endsWith('/identity/roles/search') && url.searchParams.get('search') === 'restricted'
  })
  await search.fill('restricted')
  expect((await keyResponse).ok()).toBeTruthy()
  await expect(page.getByText('Restricted', { exact: true })).toBeVisible()
  await expect(page.getByText('共 1 条', { exact: true })).toHaveCount(1)
})
