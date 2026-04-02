import { useState, useEffect } from 'react';

import Box from '@mui/material/Box';
import Button from '@mui/material/Button';

// ----------------------------------------------------------------------

const LABELS: Record<string, string> = {
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
  apple: 'Apple',
};

export function SocialLoginButtons() {
  const [providers, setProviders] = useState<string[]>([]);

  useEffect(() => {
    fetch('/api/v1/auth/providers')
      .then((r) => r.json())
      .then((d) => setProviders(d.providers || []))
      .catch(() => {});
  }, []);

  if (providers.length === 0) return null;

  return (
    <Box sx={{ mb: 3 }}>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
        {providers.map((p) => (
          <Button
            key={p}
            fullWidth
            size="large"
            variant="outlined"
            color="inherit"
            href={`/api/v1/auth/oauth/${p}?returnTo=/dashboard`}
            sx={{ textTransform: 'none', fontWeight: 600 }}
          >
            Continue with {LABELS[p] || p}
          </Button>
        ))}
      </Box>
      <Box
        sx={{
          my: 2.5,
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          '&::before, &::after': {
            content: '""',
            flex: 1,
            borderTop: '1px solid',
            borderColor: 'divider',
          },
        }}
      >
        <Box component="span" sx={{ color: 'text.disabled', fontSize: 13 }}>
          or
        </Box>
      </Box>
    </Box>
  );
}
