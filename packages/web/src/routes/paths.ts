// ----------------------------------------------------------------------

const ROOTS = {
  AUTH: '/auth',
  DASHBOARD: '/dashboard',
};

// ----------------------------------------------------------------------

export const paths = {
  auth: {
    jwt: {
      signIn: `${ROOTS.AUTH}/jwt/sign-in`,
      signUp: `${ROOTS.AUTH}/jwt/sign-up`,
    },
  },
  dashboard: {
    root: ROOTS.DASHBOARD,
    qrcodes: {
      root: `${ROOTS.DASHBOARD}/qr-codes`,
      create: `${ROOTS.DASHBOARD}/qr-codes/create`,
      edit: (token: string) => `${ROOTS.DASHBOARD}/qr-codes/${token}/edit`,
    },
    analytics: `${ROOTS.DASHBOARD}/analytics`,
    fraud: `${ROOTS.DASHBOARD}/fraud`,
    apps: {
      root: `${ROOTS.DASHBOARD}/apps`,
      create: `${ROOTS.DASHBOARD}/apps/create`,
    },
    team: `${ROOTS.DASHBOARD}/team`,
    settings: `${ROOTS.DASHBOARD}/settings`,
  },
};
