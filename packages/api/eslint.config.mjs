/**
 * Flat-config ESLint setup for packages/api (AUDIT-FINDING-012 / Audit-2 N-4).
 *
 * Replaces the legacy `.eslintrc.cjs` file, which ESLint 9 refuses to
 * load (flat-config is mandatory from v9 onwards). The rule content is
 * copied over verbatim — same four AST selectors, same message, same
 * `error` severity. The only substantive change is that the config
 * now specifies `@typescript-eslint/parser` via `languageOptions.parser`
 * so `.ts` files actually parse; the previous file ran under the
 * default espree parser, which cannot handle TypeScript syntax, so in
 * practice the rule never fired on any real source file.
 *
 * The rule flags `===` / `!==` comparisons where either operand is
 *   (a) a bare Identifier whose name ends with Signature, Mac, Hash,
 *       Challenge, or Verifier, OR
 *   (b) a MemberExpression whose property name ends with the same
 *       suffix (e.g. `session.signature`, `req.body.hash`).
 * The second case is the selector extension authorised by the Audit-2
 * N-4 second amendment — without it, every realistic route-handler
 * pattern goes uncaught because the equality sites in practice
 * compare member accesses, not bare locals. Function-call return
 * comparisons (`hmac(...) === storedMac`) are still out of scope and
 * tracked as a separate follow-up per the amendment. Test files are
 * exempted so fixture comparisons (`expect(a).toBe(b)`) do not trip
 * the rule.
 *
 * Run with:
 *   npm run lint --workspace=packages/api
 */
import tsParser from '@typescript-eslint/parser';

const CRYPTO_STRING_MESSAGE =
  'Use constantTimeEqualString from src/lib/constant-time.js for equality on cryptographic strings (AUDIT-FINDING-012).';

const CRYPTO_STRING_INEQ_MESSAGE =
  'Use constantTimeEqualString from src/lib/constant-time.js for inequality on cryptographic strings (AUDIT-FINDING-012).';

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'prisma/migrations/**',
      'test/**',
    ],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "BinaryExpression[operator='==='] > Identifier.left[name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_MESSAGE,
        },
        {
          selector:
            "BinaryExpression[operator='==='] > Identifier.right[name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_MESSAGE,
        },
        {
          selector:
            "BinaryExpression[operator='!=='] > Identifier.left[name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_INEQ_MESSAGE,
        },
        {
          selector:
            "BinaryExpression[operator='!=='] > Identifier.right[name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_INEQ_MESSAGE,
        },
        // AUDIT-2 N-4 third-amendment selectors — MemberExpression
        // coverage with a length-comparison carve-out. Shapes copied
        // verbatim from the amendment block at
        // docs/security/audit2-remediation-plan.md §N-4 lines 155-158.
        // The `:not(:has(> MemberExpression[property.name='length']))`
        // pseudo-class on the parent BinaryExpression excludes
        // length-guard idioms (`sig.length !== LENGTHS.signature`),
        // which are integer fast-reject checks, not cryptographic
        // equality.
        {
          selector:
            "BinaryExpression[operator='===']:not(:has(> MemberExpression[property.name='length'])) > MemberExpression.right[property.name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_MESSAGE,
        },
        {
          selector:
            "BinaryExpression[operator='!==']:not(:has(> MemberExpression[property.name='length'])) > MemberExpression.right[property.name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_INEQ_MESSAGE,
        },
        {
          selector:
            "BinaryExpression[operator='===']:not(:has(> MemberExpression[property.name='length'])) > MemberExpression.left[property.name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_MESSAGE,
        },
        {
          selector:
            "BinaryExpression[operator='!==']:not(:has(> MemberExpression[property.name='length'])) > MemberExpression.left[property.name=/(Signature|Mac|Hash|Challenge|Verifier)$/i]",
          message: CRYPTO_STRING_INEQ_MESSAGE,
        },
      ],
    },
  },
];
