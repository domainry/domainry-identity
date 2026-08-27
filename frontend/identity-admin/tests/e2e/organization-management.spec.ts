import { expect, test, type Page } from "@playwright/test";

async function login(page: Page) {
  await page.goto("/login");
  await page.locator("#login-username").fill("admin");
  await page.locator("#login-password").fill("Domainry@2026");
  await page.getByRole("button", { name: /登录|sign in/i }).click();
  await expect(page).not.toHaveURL(/\/login/);
}

test("organization management keeps account and department pages separate", async ({
  page,
}) => {
  await login(page);

  await page.goto("/admin/security/accounts");
  await expect(page.locator("main")).toContainText(/账号目录|Account directory/i);
  await expect(page.locator("main")).toContainText(/员工与业务档案分别在独立目录|Workforce and business profiles are managed in their own directories/i);
  await expect(page.getByRole("table")).toBeVisible();

  await page.goto("/admin/org/departments");
  await expect(page.locator("main")).toContainText(/部门|Departments/i);
  await expect(page.getByPlaceholder(/搜索组织树|Search organization tree/i)).toBeVisible();
  await expect(page.getByRole("button", { name: /新建部门|New department/i }).first()).toBeVisible();
});
