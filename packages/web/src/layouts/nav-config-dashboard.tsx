import type { NavSectionProps } from 'src/components/nav-section';

import { paths } from 'src/routes/paths';

import { CONFIG } from 'src/global-config';

import { SvgColor } from 'src/components/svg-color';

// ----------------------------------------------------------------------

const icon = (name: string) => (
  <SvgColor src={`${CONFIG.assetsDir}/assets/icons/navbar/${name}.svg`} />
);

const ICONS = {
  user: icon('ic-user'),
  lock: icon('ic-lock'),
  label: icon('ic-label'),
  params: icon('ic-params'),
  analytics: icon('ic-analytics'),
  dashboard: icon('ic-dashboard'),
};

// ----------------------------------------------------------------------

export const navData: NavSectionProps['data'] = [
  {
    subheader: 'Overview',
    items: [
      { title: 'Dashboard', path: paths.dashboard.root, icon: ICONS.dashboard },
      { title: 'QR Codes', path: paths.dashboard.qrcodes.root, icon: ICONS.label },
      { title: 'Analytics', path: paths.dashboard.analytics, icon: ICONS.analytics },
    ],
  },
  {
    subheader: 'Security',
    items: [
      { title: 'Fraud Incidents', path: paths.dashboard.fraud, icon: ICONS.lock },
    ],
  },
  {
    subheader: 'Developer',
    items: [
      { title: 'Auth Apps', path: paths.dashboard.apps.root, icon: ICONS.lock },
      { title: 'API Keys', path: paths.dashboard.apiKeys, icon: ICONS.label },
      { title: 'Webhook Logs', path: paths.dashboard.webhookLogs, icon: ICONS.params },
      { title: 'Usage', path: paths.dashboard.usage, icon: ICONS.analytics },
    ],
  },
  {
    subheader: 'Organization',
    items: [
      { title: 'Team', path: paths.dashboard.team, icon: ICONS.user },
      { title: 'Settings', path: paths.dashboard.settings, icon: ICONS.params },
    ],
  },
];
