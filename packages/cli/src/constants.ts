/** Well-known public client id of the first-party CLI app (ADR-0002 §1). */
export const QRAUTH_CLI_CLIENT_ID = 'qrauth-cli';

/** Default API origin; overridable via --api-url / QRAUTH_API_URL. */
export const DEFAULT_API_URL = 'https://qrauth.io';

/** Poll interval while waiting for approval. */
export const POLL_INTERVAL_MS = 2000;
