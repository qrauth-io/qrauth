import { test, expect } from '@playwright/test';

// Helper to create an authenticated session
async function signUp(page: import('@playwright/test').Page) {
  // Use API directly to create user + complete onboarding (faster, no browser flakiness)
  const email = `dash-${Date.now()}@example.com`;

  const signupRes = await page.request.post('http://localhost:3000/api/v1/auth/signup', {
    data: { name: 'Dashboard Tester', email, password: 'TestPass123!', organizationName: 'Dashboard Test Org' },
  });
  const { token } = await signupRes.json();

  // Complete onboarding via API
  await page.request.post('http://localhost:3000/api/v1/auth/onboarding/complete', {
    headers: { Authorization: `Bearer ${token}` },
    data: { organizationName: 'Dashboard Test Org', useCase: 'DEVELOPER' },
  });

  // Set JWT in browser — need to visit the app origin first so sessionStorage is scoped correctly
  await page.goto('/');
  await page.evaluate((t) => sessionStorage.setItem('jwt_access_token', t), token);
  await page.goto('/dashboard');
  // Wait until the auth guard resolves and dashboard content renders
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 15000 });
}

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await signUp(page);
  });

  test('should show dashboard overview', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Total QR Codes')).toBeVisible();
    await expect(page.getByText('Total Scans')).toBeVisible();
    await expect(page.getByText('Fraud Alerts')).toBeVisible();
  });

  test('should navigate to QR Codes page', async ({ page }) => {
    await page.getByRole('link', { name: 'QR Codes' }).click();
    await expect(page.getByText('New QR Code')).toBeVisible();
  });

  test('should navigate to Analytics page', async ({ page }) => {
    await page.getByRole('link', { name: 'Analytics' }).click();
    await expect(page.getByText('Analytics')).toBeVisible();
  });

  test('should navigate to Fraud Incidents page', async ({ page }) => {
    await page.getByRole('link', { name: 'Fraud Incidents' }).click();
    await expect(page.getByText('Fraud Incidents')).toBeVisible();
  });

  test('should navigate to Team page', async ({ page }) => {
    await page.getByRole('link', { name: 'Team' }).click();
    await expect(page.getByText('Team Members')).toBeVisible();
  });

  test('should navigate to Settings page', async ({ page }) => {
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page.getByText('Organization Settings')).toBeVisible();
  });
});
