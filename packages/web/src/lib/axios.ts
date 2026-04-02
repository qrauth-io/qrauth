import type { AxiosRequestConfig } from 'axios';

import axios from 'axios';

import { CONFIG } from 'src/global-config';

import { JWT_STORAGE_KEY } from 'src/auth/context/jwt/constant';

// ----------------------------------------------------------------------

const axiosInstance = axios.create({
  baseURL: CONFIG.serverUrl,
  headers: {
    'Content-Type': 'application/json',
  },
});

axiosInstance.interceptors.request.use((config) => {
  const token = sessionStorage.getItem(JWT_STORAGE_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    const message = error?.response?.data?.message || error?.message || 'Something went wrong!';
    console.error('Axios error:', message);
    return Promise.reject(new Error(message));
  }
);

export default axiosInstance;

// ----------------------------------------------------------------------

export const fetcher = async <T = unknown>(
  args: string | [string, AxiosRequestConfig]
): Promise<T> => {
  try {
    const [url, config] = Array.isArray(args) ? args : [args, {}];

    const res = await axiosInstance.get<T>(url, config);

    return res.data;
  } catch (error) {
    console.error('Fetcher failed:', error);
    throw error;
  }
};

// ----------------------------------------------------------------------

export const endpoints = {
  auth: {
    me: '/api/v1/auth/me',
    signIn: '/api/v1/auth/login',
    signUp: '/api/v1/auth/signup',
  },
  qrcodes: {
    list: '/api/v1/qrcodes',
    create: '/api/v1/qrcodes',
    details: (token: string) => `/api/v1/qrcodes/${token}`,
    bulk: '/api/v1/qrcodes/bulk',
  },
  organizations: {
    details: (id: string) => `/api/v1/organizations/${id}`,
    members: (id: string) => `/api/v1/organizations/${id}/members`,
    invitations: (id: string) => `/api/v1/organizations/${id}/invitations`,
    keys: (id: string) => `/api/v1/organizations/${id}/keys`,
    apiKeys: (id: string) => `/api/v1/organizations/${id}/api-keys`,
  },
  analytics: {
    scans: '/api/v1/analytics/scans',
    heatmap: '/api/v1/analytics/heatmap',
    fraud: '/api/v1/analytics/fraud',
    summary: '/api/v1/analytics/summary',
    fraudRules: '/api/v1/analytics/fraud-rules',
  },
  verify: {
    check: (token: string) => `/v/${token}`,
  },
  transparency: {
    log: '/api/v1/transparency/log',
    proof: (token: string) => `/api/v1/transparency/proof/${token}`,
  },
  apps: {
    list: '/api/v1/apps',
    create: '/api/v1/apps',
    details: (id: string) => `/api/v1/apps/${id}`,
    rotateSecret: (id: string) => `/api/v1/apps/${id}/rotate-secret`,
  },
  onboarding: {
    complete: '/api/v1/auth/onboarding/complete',
  },
} as const;
