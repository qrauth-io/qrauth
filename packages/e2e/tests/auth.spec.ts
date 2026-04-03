import { test, expect } from '@playwright/test';

const TEST_USER = {
  name: 'Test User',
  email: `test-${Date.now()}@example.com`,
  password: 'TestPass123!',
  organizationName: 'Test Municipality',
};

test.describe('Authentication', () => {
  test('should show sign-in page', async ({ page }) => {
    await page.goto('/auth/jwt/sign-in');
    await expect(page.getByText('Sign in to QRAuth')).toBeVisible();
    await expect(page.getByLabel('Email address')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
  });

  test('should show sign-up page', async ({ page }) => {
    await page.goto('/auth/jwt/sign-up');
    await expect(page.getByText('Create your QRAuth account')).toBeVisible();
  });

  test('should show validation errors on empty sign-in', async ({ page }) => {
    await page.goto('/auth/jwt/sign-in');
    await page.getByRole('button', { name: 'Sign in' }).click();
    // Should show validation errors
    await expect(page.locator('text=required').first()).toBeVisible({ timeout: 5000 });
  });

  test('should sign up a new user', async ({ page }) => {
    await page.goto('/auth/jwt/sign-up');

    await page.getByLabel('Full name').fill(TEST_USER.name);
    await page.getByLabel('Organization name').fill(TEST_USER.organizationName);
    await page.getByLabel('Email address').fill(TEST_USER.email);
    await page.getByLabel('Password').fill(TEST_USER.password);

    await page.getByRole('button', { name: 'Create account' }).click();

    // Should redirect to onboarding (new user) or dashboard
    await expect(page).toHaveURL(/\/(onboarding|dashboard)/, { timeout: 10000 });
  });

  test('should sign in with existing user', async ({ page }) => {
    // First sign up
    await page.goto('/auth/jwt/sign-up');
    const email = `signin-${Date.now()}@example.com`;

    await page.getByLabel('Full name').fill('Sign In Test');
    await page.getByLabel('Organization name').fill('Sign In Org');
    await page.getByLabel('Email address').fill(email);
    await page.getByLabel('Password').fill('TestPass123!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/\/(onboarding|dashboard)/, { timeout: 10000 });

    // Complete onboarding if needed so user has onboardedAt set
    if (page.url().includes('/onboarding')) {
      await page.getByRole('button', { name: 'Continue' }).click();
      await page.getByText('Developer').click();
      await page.getByRole('button', { name: 'Continue' }).click();
      await page.getByRole('button', { name: 'Skip' }).click();
      await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
    }

    // Sign out (clear session)
    await page.evaluate(() => sessionStorage.clear());
    await page.goto('/auth/jwt/sign-in');

    // Sign in
    await page.getByLabel('Email address').fill(email);
    await page.getByLabel('Password').fill('TestPass123!');
    await page.getByRole('button', { name: 'Sign in' }).click();

    // Onboarded user goes straight to dashboard
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
  });

  test('should fail sign-in with wrong password', async ({ page }) => {
    await page.goto('/auth/jwt/sign-in');

    await page.getByLabel('Email address').fill('nonexistent@example.com');
    await page.getByLabel('Password').fill('wrongpassword');
    await page.getByRole('button', { name: 'Sign in' }).click();

    // Should show error
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
  });

  test('should redirect unauthenticated users to sign-in', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/sign-in/, { timeout: 10000 });
  });
});
