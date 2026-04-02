import * as z from 'zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import Box from '@mui/material/Box';
import Link from '@mui/material/Link';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';

import { paths } from 'src/routes/paths';
import { RouterLink } from 'src/routes/components';

import axios from 'src/lib/axios';

import { Form, Field, schemaUtils } from 'src/components/hook-form';

import { FormHead } from '../../components/form-head';

// ----------------------------------------------------------------------

const ForgotSchema = z.object({
  email: schemaUtils.email(),
});

export function JwtForgotPasswordView() {
  const [sent, setSent] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const methods = useForm({
    resolver: zodResolver(ForgotSchema as any),
    defaultValues: { email: '' },
  });

  const { handleSubmit, formState: { isSubmitting } } = methods;

  const onSubmit = handleSubmit(async (data) => {
    try {
      await axios.post('/api/v1/auth/forgot-password', { email: data.email });
      setSent(true);
    } catch (error: any) {
      setErrorMessage(error.message || 'Something went wrong');
    }
  });

  if (sent) {
    return (
      <>
        <FormHead
          title="Check your email"
          description="If an account exists, we've sent a password reset link."
          sx={{ textAlign: { xs: 'center', md: 'left' } }}
        />
        <Alert severity="success" sx={{ mb: 3 }}>
          Check your inbox for the reset link.
        </Alert>
        <Link component={RouterLink} href={paths.auth.jwt.signIn} variant="subtitle2">
          Back to sign in
        </Link>
      </>
    );
  }

  return (
    <>
      <FormHead
        title="Forgot your password?"
        description={
          <>
            Enter your email and we&apos;ll send you a reset link.{' '}
            <Link component={RouterLink} href={paths.auth.jwt.signIn} variant="subtitle2">
              Back to sign in
            </Link>
          </>
        }
        sx={{ textAlign: { xs: 'center', md: 'left' } }}
      />

      {errorMessage && <Alert severity="error" sx={{ mb: 3 }}>{errorMessage}</Alert>}

      <Form methods={methods} onSubmit={onSubmit}>
        <Box sx={{ gap: 3, display: 'flex', flexDirection: 'column' }}>
          <Field.Text name="email" label="Email address" slotProps={{ inputLabel: { shrink: true } }} />
          <Button fullWidth color="inherit" size="large" type="submit" variant="contained" loading={isSubmitting}>
            Send Reset Link
          </Button>
        </Box>
      </Form>
    </>
  );
}
