/**
 * Smoke test — core user journey:
 *   Register → Create project → Lab loads → Save persists → Reload preserves data
 *
 * Requires both servers to be running:
 *   Backend:  uvicorn app.main:app --reload   (port 8000)
 *   Frontend: npm run dev                     (port 5173)
 */
import { test, expect } from '@playwright/test'

const password = 'TestPass123'

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function register(page: import('@playwright/test').Page, email: string) {
  await page.goto('/register')
  await page.locator('input[type="email"]').fill(email)
  await page.locator('input[type="password"]').first().fill(password)
  await page.locator('input[type="password"]').nth(1).fill(password)   // confirm field
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 })
}

async function createProject(page: import('@playwright/test').Page, name: string) {
  await page.getByRole('button', { name: 'New project' }).click()
  // Wait for the template modal to appear, then click the Blank Canvas button
  await page.getByRole('button', { name: /blank canvas/i }).click()
  // Wait for the details step (name input) to appear
  const nameInput = page.getByPlaceholder('My first lab')
  await nameInput.waitFor({ state: 'visible' })
  await nameInput.fill(name)
  await page.getByRole('button', { name: 'Create', exact: true }).click()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test('register → dashboard → create project → lab loads', async ({ page }) => {
  const email = `smoke+${Date.now()}@example.com`
  const projectName = `Smoke Lab ${Date.now()}`

  await register(page, email)

  // Email visible in top-right nav
  await expect(page.getByText(email)).toBeVisible()

  // Create a project
  await createProject(page, projectName)

  // Should navigate to /lab/<id>
  await expect(page).toHaveURL(/\/lab\/\d+/, { timeout: 10_000 })

  // Project name visible in the header
  await expect(page.getByText(projectName)).toBeVisible()

  // ReactFlow canvas is present
  await expect(page.locator('.react-flow')).toBeVisible()

  // Back to dashboard — project card is there
  page.once('dialog', dialog => dialog.accept())
  await page.locator('header button').first().click()
  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 })
  await expect(page.getByText(projectName)).toBeVisible()
})

test('duplicate project name shows inline error', async ({ page }) => {
  const email = `dup+${Date.now()}@example.com`
  const name = `DupTest ${Date.now()}`

  await register(page, email)

  // First creation → navigates to lab
  await createProject(page, name)
  await expect(page).toHaveURL(/\/lab\/\d+/, { timeout: 10_000 })

  // Go back to dashboard and try the same name again
  await page.goto('/dashboard')
  await createProject(page, name)

  // Should NOT navigate — inline error must appear
  await expect(page.getByText(/already exists/i)).toBeVisible()
  await expect(page).toHaveURL(/dashboard/)
})

test('lab reloads topology after page refresh', async ({ page }) => {
  const email = `reload+${Date.now()}@example.com`
  const name = `ReloadTest ${Date.now()}`

  await register(page, email)
  await createProject(page, name)
  await expect(page).toHaveURL(/\/lab\/\d+/, { timeout: 10_000 })

  const labUrl = page.url()

  // Wait for autosave — text is "Saved 4:30:15 PM" (locale time string)
  await expect(page.getByText(/^Saved /)).toBeVisible({ timeout: 10_000 })

  // Reload the page
  await page.reload()
  await expect(page).toHaveURL(labUrl)

  // Project name and canvas still present
  await expect(page.getByText(name)).toBeVisible()
  await expect(page.locator('.react-flow')).toBeVisible()
})
