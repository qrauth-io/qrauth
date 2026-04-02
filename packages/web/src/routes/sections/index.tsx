import type { RouteObject } from 'react-router';

import { lazy, Suspense } from 'react';

import { LoadingScreen } from 'src/components/loading-screen';

import { AuthGuard } from 'src/auth/guard';

import { authRoutes } from './auth';
import { dashboardRoutes } from './dashboard';

// ----------------------------------------------------------------------

const Page404 = lazy(() => import('src/pages/error/404'));
const HomePage = lazy(() => import('src/pages/home'));
const OnboardingPage = lazy(() => import('src/pages/onboarding'));

export const routesSection: RouteObject[] = [
  {
    path: '/',
    element: <HomePage />,
  },

  // Onboarding
  {
    path: 'onboarding',
    element: (
      <AuthGuard>
        <Suspense fallback={<LoadingScreen />}>
          <OnboardingPage />
        </Suspense>
      </AuthGuard>
    ),
  },

  // Auth
  ...authRoutes,

  // Dashboard
  ...dashboardRoutes,

  // No match
  { path: '*', element: <Page404 /> },
];
