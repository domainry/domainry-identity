import { defineConfig, devices } from '@playwright/test'

const baseURL = process.env.IDENTITY_ADMIN_URL ?? 'http://127.0.0.1:3103'
const frontendURL = new URL(baseURL)
const frontendPort = frontendURL.port || (frontendURL.protocol === 'https:' ? '443' : '80')

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: 'list',
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `npm run dev -- --host ${frontendURL.hostname} --port ${frontendPort}`,
    url: baseURL,
    reuseExistingServer: true,
    timeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
