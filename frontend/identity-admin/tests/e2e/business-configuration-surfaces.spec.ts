import { expect, test } from '@playwright/test'

async function login(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.locator('#login-username').fill('admin')
  await page.locator('#login-password').fill('Domainry@2026')
  await page.getByRole('button', { name: /登录|sign in/i }).click()
  await expect(page).not.toHaveURL(/\/login/)
}

test('dictionary and field-permission support keys expose dedicated domain surfaces', async ({ page }) => {
  await login(page)
  await page.goto('/admin/system/dictionaries')
  await expect(page.locator('main')).toContainText(/字典|Dictionaries/i)
  await expect(page.locator('textarea')).toHaveCount(0)

  await page.goto('/admin/org/field-permissions')
  await expect(page.locator('main')).toContainText(/字段权限|Field Permissions/i)
  await expect(page.getByRole('table')).toBeVisible()
})
