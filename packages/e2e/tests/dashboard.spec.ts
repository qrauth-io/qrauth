import { test, expect } from '@playwright/test';

// Helper to create an authenticated session
async function signUp(page: import('@playwright/test').Page) {
  const email = `dash-${Date.now()}@example.com`;
  await page.goto('/auth/jwt/sign-up');
  await page.getByLabel('Full name').fill('Dashboard Tester');
  await page.getByLabel('Organization name').fill('Dashboard Test Org');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('TestPass123!');
  await page.getByRole('button', { name: 'Create account' }).click();

  // Complete onboarding if redirected there
  try {
    await expect(page).toHaveURL(/\/onboarding/, { timeout: 5000 });
    // Step 1: org name is pre-filled, click Continue
    await page.getByRole('button', { name: 'Continue' }).click();
    // Step 2: select use case
    await page.getByText('Developer').click();
    await page.getByRole('button', { name: 'Continue' }).click();
    // Step 3: skip QR creation
    await page.getByRole('button', { name: 'Skip' }).click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
  } catch {
    // If already on dashboard (onboarding was skipped), continue
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
  }
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
