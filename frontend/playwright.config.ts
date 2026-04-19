import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright E2E configuration.
 *
 * Prerequisites before running `npm run test:e2e`:
 *   1. Backend:  cd backend && uvicorn app.main:app --reload   (port 8000)
 *   2. Frontend: cd frontend && npm run dev                    (port 5173)
 *
 * First-time setup:
 *   npx playwright install chromium
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: 'http://localhost:5173',
    headless: false,
    launchOptions: { slowMo: 1000 },
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
