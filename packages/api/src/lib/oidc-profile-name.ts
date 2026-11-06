/**
 * The `name` claim for the OIDC `profile` scope, or undefined when there is no
 * real name. Accounts created from a provider that sent no name (Apple after
 * the first sign-in, Microsoft without a display name) store the email as the
 * name; apps should not receive that as if it were a name.
 */
export function profileNameClaim(user: { name: string; email: string }): string | undefined {
  const name = user.name.trim();
  if (!name || name.toLowerCase() === user.email.trim().toLowerCase()) return undefined;
  return name;
}
