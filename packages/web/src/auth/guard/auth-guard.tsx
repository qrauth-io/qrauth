import { useState, useEffect } from 'react';

import { paths } from 'src/routes/paths';
import { useRouter, usePathname } from 'src/routes/hooks';

import { CONFIG } from 'src/global-config';

import { SplashScreen } from 'src/components/loading-screen';

import { useAuthContext } from '../hooks';

// ----------------------------------------------------------------------

type AuthGuardProps = {
  children: React.ReactNode;
};

const signInPaths: Record<string, string> = {
  jwt: paths.auth.jwt.signIn,
};

export function AuthGuard({ children }: AuthGuardProps) {
  const router = useRouter();
  const pathname = usePathname();

  const { authenticated, loading, user } = useAuthContext();

  const [isChecking, setIsChecking] = useState(true);

  const createRedirectPath = (currentPath: string) => {
    const queryString = new URLSearchParams({ returnTo: pathname }).toString();
    return `${currentPath}?${queryString}`;
  };

  useEffect(() => {
    if (loading) return;

    if (!authenticated) {
      const { method } = CONFIG.auth;
      const signInPath = signInPaths[method];
      router.replace(createRedirectPath(signInPath));
      return;
    }

    // Redirect to onboarding if user hasn't completed it
    if (user && !(user as any).onboardedAt && !pathname.startsWith('/onboarding')) {
      router.replace('/onboarding');
      return;
    }

    // Authenticated (and onboarded or on onboarding page) — render children
    setIsChecking(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, loading, pathname]);

  if (isChecking) {
    return <SplashScreen />;
  }

  return <>{children}</>;
}
