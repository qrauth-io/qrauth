import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test('should show dashboard overview and navigate all pages', async ({ page }) => {
    // Sign up + onboard via browser (one-time cost)
    const email = `dash-${Date.now()}@example.com`;
    await page.goto('/auth/jwt/sign-up');
    await page.getByLabel('Full name').fill('Dashboard Tester');
    await page.getByLabel('Organization name').fill('Dashboard Test Org');
    await page.getByLabel('Email address').fill(email);
    await page.getByLabel('Password').fill('TestPass123!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/\/(onboarding|dashboard)/, { timeout: 15000 });

    if (page.url().includes('/onboarding')) {
      await page.getByRole('button', { name: 'Continue' }).click();
      await page.getByText('Developer').click();
      await page.getByRole('button', { name: 'Continue' }).click();
      await page.getByRole('button', { name: 'Skip' }).click();
      await expect(page).toHaveURL(/\/dashboard/, { timeout: 15000 });
    }

    // Dashboard overview
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Total QR Codes')).toBeVisible();
    await expect(page.getByText('Total Scans')).toBeVisible();
    await expect(page.getByText('Fraud Alerts')).toBeVisible();

    // Navigate to QR Codes
    await page.getByRole('link', { name: 'QR Codes' }).click();
    await expect(page.getByText('New QR Code')).toBeVisible();

    // Navigate to Analytics
    await page.getByRole('link', { name: 'Analytics' }).click();
    await expect(page.getByText('Analytics')).toBeVisible();

    // Navigate to Fraud Incidents
    await page.getByRole('link', { name: 'Fraud Incidents' }).click();
    await expect(page.getByText('Fraud Incidents')).toBeVisible();

    // Navigate to Team
    await page.getByRole('link', { name: 'Team' }).click();
    await expect(page.getByText('Team Members')).toBeVisible();

    // Navigate to Settings
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page.getByText('Organization Settings')).toBeVisible();
  });
});
