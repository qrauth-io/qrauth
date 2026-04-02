import type { RouteObject } from 'react-router';

import { Outlet } from 'react-router';
import { lazy, Suspense } from 'react';

import { CONFIG } from 'src/global-config';
import { DashboardLayout } from 'src/layouts/dashboard';

import { LoadingScreen } from 'src/components/loading-screen';

import { AuthGuard } from 'src/auth/guard';

import { usePathname } from '../hooks';

// ----------------------------------------------------------------------

const OverviewPage = lazy(() => import('src/pages/dashboard/overview'));
const QRCodesPage = lazy(() => import('src/pages/dashboard/qr-codes'));
const QRCodesCreatePage = lazy(() => import('src/pages/dashboard/qr-codes-create'));
const QRCodesEditPage = lazy(() => import('src/pages/dashboard/qr-codes-edit'));
const QRCodesBulkPage = lazy(() => import('src/pages/dashboard/qr-codes-bulk'));
const AnalyticsPage = lazy(() => import('src/pages/dashboard/analytics'));
const FraudPage = lazy(() => import('src/pages/dashboard/fraud'));
const TeamPage = lazy(() => import('src/pages/dashboard/team'));
const SettingsPage = lazy(() => import('src/pages/dashboard/settings'));
const AppsPage = lazy(() => import('src/pages/dashboard/apps'));

// ----------------------------------------------------------------------

function SuspenseOutlet() {
  const pathname = usePathname();
  return (
    <Suspense key={pathname} fallback={<LoadingScreen />}>
      <Outlet />
    </Suspense>
  );
}

const dashboardLayout = () => (
  <DashboardLayout>
    <SuspenseOutlet />
  </DashboardLayout>
);

export const dashboardRoutes: RouteObject[] = [
  {
    path: 'dashboard',
    element: CONFIG.auth.skip ? dashboardLayout() : <AuthGuard>{dashboardLayout()}</AuthGuard>,
    children: [
      { element: <OverviewPage />, index: true },
      { path: 'qr-codes', element: <QRCodesPage /> },
      { path: 'qr-codes/create', element: <QRCodesCreatePage /> },
      { path: 'qr-codes/bulk', element: <QRCodesBulkPage /> },
      { path: 'qr-codes/:token/edit', element: <QRCodesEditPage /> },
      { path: 'analytics', element: <AnalyticsPage /> },
      { path: 'fraud', element: <FraudPage /> },
      { path: 'team', element: <TeamPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: 'apps', element: <AppsPage /> },
    ],
  },
];
