import * as z from 'zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { useBoolean } from 'minimal-shared/hooks';
import { zodResolver } from '@hookform/resolvers/zod';

import Box from '@mui/material/Box';
import Link from '@mui/material/Link';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';

import { paths } from 'src/routes/paths';
import { useSearchParams } from 'src/routes/hooks';
import { RouterLink } from 'src/routes/components';

import axios from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { Form, Field } from 'src/components/hook-form';

import { FormHead } from '../../components/form-head';

// ----------------------------------------------------------------------

const ResetSchema = z.object({
  password: z.string().min(8, 'Password must be at least 8 characters'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export function JwtResetPasswordView() {
  const searchParams = useSearchParams();
  const token = searchParams.get('token');

  const showPassword = useBoolean();
  const [success, setSuccess] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const methods = useForm({
    resolver: zodResolver(ResetSchema as any),
    defaultValues: { password: '', confirmPassword: '' },
  });

  const { handleSubmit, formState: { isSubmitting } } = methods;

  const onSubmit = handleSubmit(async (data) => {
    try {
      await axios.post('/api/v1/auth/reset-password', { token, password: data.password });
      setSuccess(true);
    } catch (error: any) {
      setErrorMessage(error.message || 'Invalid or expired reset token');
    }
  });

  if (!token) {
    return (
      <>
        <FormHead title="Invalid Link" description="This password reset link is invalid or has expired." sx={{ textAlign: { xs: 'center', md: 'left' } }} />
        <Link component={RouterLink} href={paths.auth.jwt.forgotPassword} variant="subtitle2">
          Request a new link
        </Link>
      </>
    );
  }

  if (success) {
    return (
      <>
        <FormHead title="Password Reset" description="Your password has been reset successfully." sx={{ textAlign: { xs: 'center', md: 'left' } }} />
        <Alert severity="success" sx={{ mb: 3 }}>You can now sign in with your new password.</Alert>
        <Link component={RouterLink} href={paths.auth.jwt.signIn} variant="subtitle2">
          Sign in
        </Link>
      </>
    );
  }

  return (
    <>
      <FormHead title="Set new password" description="Enter your new password below." sx={{ textAlign: { xs: 'center', md: 'left' } }} />

      {errorMessage && <Alert severity="error" sx={{ mb: 3 }}>{errorMessage}</Alert>}

      <Form methods={methods} onSubmit={onSubmit}>
        <Box sx={{ gap: 3, display: 'flex', flexDirection: 'column' }}>
          <Field.Text
            name="password"
            label="New Password"
            type={showPassword.value ? 'text' : 'password'}
            slotProps={{
              inputLabel: { shrink: true },
              input: {
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={showPassword.onToggle} edge="end">
                      <Iconify icon={showPassword.value ? 'solar:eye-bold' : 'solar:eye-closed-bold'} />
                    </IconButton>
                  </InputAdornment>
                ),
              },
            }}
          />
          <Field.Text name="confirmPassword" label="Confirm Password" type="password" slotProps={{ inputLabel: { shrink: true } }} />
          <Button fullWidth color="inherit" size="large" type="submit" variant="contained" loading={isSubmitting}>
            Reset Password
          </Button>
        </Box>
      </Form>
    </>
  );
}
