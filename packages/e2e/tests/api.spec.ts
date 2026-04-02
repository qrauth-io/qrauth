import { test, expect } from '@playwright/test';

const API_URL = 'http://localhost:3000';

test.describe('API', () => {
  test('health check', async ({ request }) => {
    const response = await request.get(`${API_URL}/health`);
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.status).toBe('ok');
  });

  test('signup creates user and org', async ({ request }) => {
    const email = `api-${Date.now()}@example.com`;
    const response = await request.post(`${API_URL}/api/v1/auth/signup`, {
      data: {
        name: 'API Test User',
        email,
        password: 'TestPass123!',
        organizationName: 'API Test Org',
      },
    });
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.token).toBeTruthy();
    expect(body.user.email).toBe(email);
    expect(body.organization.name).toBe('API Test Org');
  });

  test('login returns token', async ({ request }) => {
    const email = `login-${Date.now()}@example.com`;

    // Sign up first
    await request.post(`${API_URL}/api/v1/auth/signup`, {
      data: {
        name: 'Login Test',
        email,
        password: 'TestPass123!',
        organizationName: 'Login Org',
      },
    });

    // Login
    const response = await request.post(`${API_URL}/api/v1/auth/login`, {
      data: { email, password: 'TestPass123!' },
    });
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.token).toBeTruthy();
    expect(body.user.email).toBe(email);
  });

  test('authenticated endpoints require token', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/v1/qrcodes`);
    expect(response.status()).toBe(401);
  });

  test('can create and list QR codes', async ({ request }) => {
    const email = `qr-${Date.now()}@example.com`;

    // Sign up
    const signupRes = await request.post(`${API_URL}/api/v1/auth/signup`, {
      data: {
        name: 'QR Test',
        email,
        password: 'TestPass123!',
        organizationName: 'QR Org',
      },
    });
    const { token } = await signupRes.json();

    // Complete onboarding (creates signing key)
    await request.post(`${API_URL}/api/v1/auth/onboarding/complete`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { organizationName: 'QR Org', useCase: 'DEVELOPER' },
    });

    // Create QR code
    const createRes = await request.post(`${API_URL}/api/v1/qrcodes`, {
      headers: { Authorization: `Bearer ${token}` },
      data: {
        destinationUrl: 'https://example.com/pay',
        label: 'Test QR Code',
        location: { lat: 40.6321, lng: 22.9414, radiusM: 50 },
      },
    });
    expect(createRes.ok()).toBeTruthy();
    const qr = await createRes.json();
    expect(qr.token).toBeTruthy();
    expect(qr.signature).toBeTruthy();

    // List QR codes
    const listRes = await request.get(`${API_URL}/api/v1/qrcodes`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(listRes.ok()).toBeTruthy();
    const list = await listRes.json();
    expect(list.data.length).toBeGreaterThanOrEqual(1);
  });

  test('public verification endpoint works', async ({ request }) => {
    const email = `verify-${Date.now()}@example.com`;

    // Sign up + create QR
    const signupRes = await request.post(`${API_URL}/api/v1/auth/signup`, {
      data: {
        name: 'Verify Test',
        email,
        password: 'TestPass123!',
        organizationName: 'Verify Org',
      },
    });
    const { token: authToken } = await signupRes.json();

    // Complete onboarding
    await request.post(`${API_URL}/api/v1/auth/onboarding/complete`, {
      headers: { Authorization: `Bearer ${authToken}` },
      data: { organizationName: 'Verify Org', useCase: 'DEVELOPER' },
    });

    const createRes = await request.post(`${API_URL}/api/v1/qrcodes`, {
      headers: { Authorization: `Bearer ${authToken}` },
      data: {
        destinationUrl: 'https://example.com/verify-test',
        label: 'Verify Test QR',
      },
    });
    const qr = await createRes.json();

    // Verify (public endpoint — request JSON explicitly)
    const verifyRes = await request.get(`${API_URL}/v/${qr.token}`, {
      headers: { Accept: 'application/json' },
    });
    expect(verifyRes.ok()).toBeTruthy();
    const verification = await verifyRes.json();
    expect(verification.verified).toBe(true);
    expect(verification.organization).toBeTruthy();
  });

  test('transparency log is public', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/v1/transparency/log`);
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.data).toBeInstanceOf(Array);
  });
});
