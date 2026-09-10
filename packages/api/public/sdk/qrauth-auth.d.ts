/**
 * QRAuth SDK — TypeScript type definitions
 * https://qrauth.io
 *
 * Supports two usage patterns:
 *
 *   1. Global script tag (UMD):
 *      <script src="https://qrauth.io/sdk/qrauth-auth.js"></script>
 *      // window.QRAuth is available globally
 *
 *   2. Module consumer (bundler / TypeScript project):
 *      /// <reference types="./qrauth-auth" />
 *      import QRAuth from './qrauth-auth';
 */

// ---------------------------------------------------------------------------
// Session status
// ---------------------------------------------------------------------------

/**
 * Canonical status values returned by the QRAuth API.
 *
 * - `PENDING`  — session created, waiting for the user to scan the QR code.
 * - `SCANNED`  — QR code has been scanned; waiting for the user to approve or
 *                deny the login on their device.
 * - `APPROVED` — the user approved the login. `onSuccess` is fired.
 * - `DENIED`   — the user explicitly denied the login. `onDeny` is fired.
 * - `EXPIRED`  — the session TTL elapsed without resolution. `onExpire` is
 *                fired.
 */
export type QRAuthStatus = 'PENDING' | 'SCANNED' | 'APPROVED' | 'DENIED' | 'EXPIRED';

// ---------------------------------------------------------------------------
// QRAuthResult / QRAuthSessionData
// ---------------------------------------------------------------------------

/**
 * The payload delivered to `onSuccess`, `onScan`, and `onDeny` callbacks.
 *
 * This is the raw JSON body returned by `GET /api/v1/auth-sessions/:id` (the
 * polling endpoint). All three callbacks receive the same shape so that
 * callers can share a single type for all session-state handlers.
 */
export interface QRAuthSessionData {
  /** Unique identifier of the auth session. */
  sessionId: string;

  /**
   * Current session status.
   * @see QRAuthStatus
   */
  status: QRAuthStatus;

  /**
   * OAuth-style scopes that were requested when the session was created.
   * Defaults to `['identity', 'email']`.
   */
  scopes: string[];

  /**
   * Authenticated user data. Populated once the session reaches `APPROVED`
   * status; `null` in earlier states.
   */
  user: {
    /** Platform-internal user ID. */
    id: string;
    /** Display name, if granted by the `identity` scope. */
    name?: string;
    /** Email address, if granted by the `email` scope. */
    email?: string;
  } | null;

  /**
   * ECDSA-P256 signature over the session result, produced by the QRAuth
   * signing key. Null until the session is resolved.
   */
  signature: string | null;

  /** ISO 8601 timestamp at which the session expires. */
  expiresAt: string;

  /**
   * ISO 8601 timestamp at which the QR code was physically scanned.
   * Null while the session is still `PENDING`.
   */
  scannedAt: string | null;

  /**
   * ISO 8601 timestamp at which the session was resolved (`APPROVED` or
   * `DENIED`). Null until resolution.
   */
  resolvedAt: string | null;
}

/**
 * Alias for `QRAuthSessionData`. Used as the argument type of `onSuccess` to
 * make it explicit that the result is a fully resolved session.
 *
 * At the point `onSuccess` fires, `user` is populated, `signature` is set,
 * and `resolvedAt` is non-null.
 */
export type QRAuthResult = QRAuthSessionData;

// ---------------------------------------------------------------------------
// QRAuthOptions
// ---------------------------------------------------------------------------

/**
 * Configuration passed to the `QRAuth` constructor.
 */
export interface QRAuthOptions {
  /**
   * The application client ID obtained from the QRAuth dashboard.
   *
   * Required. The constructor throws synchronously if this is missing.
   *
   * @example 'qrauth_app_01HXYZ...'
   */
  clientId: string;

  /**
   * The application client secret.
   *
   * **Server-side use only.** Never include this in browser-side code — use
   * the PKCE flow (omit `clientSecret`) for all browser deployments.
   *
   * When present, HTTP Basic auth (`clientId:clientSecret`) is used instead
   * of the PKCE `X-Client-Id` header.
   *
   * @example 'qrauth_secret_01HXYZ...'
   */
  clientSecret?: string;

  /**
   * A CSS selector string or an `HTMLElement` reference for the container
   * that should host the "Sign in with QRAuth" button.
   *
   * When provided, `render()` is called automatically during construction.
   * When omitted, call `render()` or `start()` manually.
   *
   * @example '#qrauth-auth'
   * @example document.getElementById('my-login-widget')
   */
  element?: string | HTMLElement;

  /**
   * Override the QRAuth API base URL.
   *
   * Defaults to `'https://qrauth.io'`. Useful for self-hosted deployments or
   * local development environments.
   *
   * @default 'https://qrauth.io'
   */
  baseUrl?: string;

  /**
   * OAuth-style scopes to request for the session.
   *
   * The QRAuth user will be shown which scopes your app is requesting before
   * they approve the login on their device.
   *
   * @default ['identity', 'email']
   */
  scopes?: string[];

  /**
   * Called when the user successfully approves the login on their device.
   *
   * The `result` argument contains the verified session data including user
   * identity and the server-side ECDSA signature.
   *
   * The modal auto-closes 2 seconds after this callback fires.
   */
  onSuccess?: (result: QRAuthResult) => void;

  /**
   * Called when an unrecoverable error occurs — for example, a network
   * failure while creating the session, or a PKCE challenge generation error.
   *
   * The SDK does **not** close the modal automatically on error; you may call
   * `close()` inside this handler if desired.
   */
  onError?: (error: Error) => void;

  /**
   * Called when the QR code is physically scanned by the user's device, but
   * before they approve or deny the login.
   *
   * Use this to show feedback such as "Scan detected — please confirm on your
   * phone" in your own UI.
   */
  onScan?: (data: QRAuthSessionData) => void;

  /**
   * Called when the session expires without being resolved.
   *
   * The modal transitions to an "expired" state and offers a retry button.
   * You may also call `start()` programmatically to create a fresh session.
   */
  onExpire?: () => void;

  /**
   * Called when the user explicitly denies the login request on their device.
   *
   * The `data` argument reflects the final session state including the
   * `DENIED` status.
   */
  onDeny?: (data: QRAuthSessionData) => void;
}

// ---------------------------------------------------------------------------
// QRAuth class
// ---------------------------------------------------------------------------

/**
 * Main SDK class. Manages the full lifecycle of a QR-based authentication
 * session: session creation, QR code display, real-time status polling, and
 * callback dispatch.
 *
 * @example
 * // Minimal PKCE setup — auto-renders a button into the container element
 * const auth = new QRAuth({
 *   clientId: 'qrauth_app_xxx',
 *   element: '#qrauth-auth',
 *   onSuccess: (result) => {
 *     console.log('Logged in as', result.user?.email);
 *   },
 *   onError: (err) => {
 *     console.error('Auth error:', err.message);
 *   },
 * });
 *
 * @example
 * // Manual start — no element, trigger the modal from your own button
 * const auth = new QRAuth({ clientId: 'qrauth_app_xxx' });
 * document.getElementById('my-btn').addEventListener('click', () => auth.start());
 */
export declare class QRAuth {
  /**
   * Instantiate the SDK. Throws synchronously if `options.clientId` is not
   * provided.
   *
   * If `options.element` is supplied and resolves to a DOM element, `render()`
   * is called automatically before the constructor returns.
   *
   * @throws {Error} When `clientId` is missing from `options`.
   */
  constructor(options: QRAuthOptions);

  /**
   * Inject the "Sign in with QRAuth" button into the container element that
   * was supplied via `options.element`.
   *
   * This is a no-op when no container element was provided at construction
   * time. Safe to call multiple times — the container is cleared before
   * re-rendering.
   */
  render(): void;

  /**
   * Create a new auth session and open the QR code modal.
   *
   * Behaviour depends on how the instance was configured:
   *
   * - **PKCE flow** (no `clientSecret`): generates a `code_verifier` /
   *   `code_challenge` pair via `crypto.subtle`, then POSTs to
   *   `/api/v1/auth-sessions` with the challenge attached.
   * - **Legacy flow** (`clientSecret` present): POSTs directly using HTTP
   *   Basic auth.
   *
   * Polling begins as soon as the session is created. Status changes trigger
   * the appropriate callbacks (`onScan`, `onSuccess`, `onDeny`, `onExpire`).
   *
   * Calling `start()` while a session is already active will create a second
   * session; call `close()` first to clean up the previous one.
   */
  start(): void;

  /**
   * Close and remove the QR modal overlay from the DOM, stop all polling
   * timers, and discard the current PKCE code verifier.
   *
   * Does **not** clear the container element rendered by `render()`. Call
   * `destroy()` if you want to remove the button as well.
   *
   * Safe to call when no modal is open.
   */
  close(): void;

  /**
   * Close the modal (calls `close()`) **and** clear the container element
   * that was supplied via `options.element`, removing the rendered button
   * from the DOM.
   *
   * After `destroy()` the instance should be discarded — call the
   * constructor again if you need a fresh widget.
   */
  destroy(): void;
}

// ---------------------------------------------------------------------------
// Global augmentation (UMD / script-tag usage)
// ---------------------------------------------------------------------------

declare global {
  interface Window {
    /**
     * The `QRAuth` constructor exposed on `window` when the SDK is loaded as
     * a plain `<script>` tag (UMD build).
     *
     * @example
     * const auth = new window.QRAuth({ clientId: 'qrauth_app_xxx' });
     */
    QRAuth: typeof QRAuth;
  }
}

// ---------------------------------------------------------------------------
// Module default export (bundler / ESM usage)
// ---------------------------------------------------------------------------

export default QRAuth;
