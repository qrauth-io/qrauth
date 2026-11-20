/**
 * Flat-config ESLint for @qrauth/merkle-log.
 *
 * Same constant-time rule as packages/api/eslint.config.mjs
 * (AUDIT-FINDING-012): `===` / `!==` on identifiers or members whose name
 * ends with Signature, Mac, Hash, Challenge, Verifier or Root is an error.
 * Hash and root comparisons go through constantTimeEqual (src/bytes.ts).
 * Length comparisons (`x.length !== size`) stay allowed.
 */
import tsParser from '@typescript-eslint/parser';

const MESSAGE = 'Use constantTimeEqual from src/bytes.ts for equality on hashes and roots (AUDIT-FINDING-012).';
const NAME = '/(Signature|Mac|Hash|Challenge|Verifier|Root)$/i';
const NOT_LENGTH = ":not(:has(> MemberExpression[property.name='length']))";

const selectors = [];
for (const op of ['===', '!==', '==', '!=']) {
  for (const side of ['left', 'right']) {
    selectors.push({ selector: `BinaryExpression[operator='${op}'] > Identifier.${side}[name=${NAME}]`, message: MESSAGE });
    selectors.push({
      selector: `BinaryExpression[operator='${op}']${NOT_LENGTH} > MemberExpression.${side}[property.name=${NAME}]`,
      message: MESSAGE,
    });
  }
}

export default [
  { ignores: ['dist/**', 'node_modules/**', 'test/**'] },
  {
    files: ['src/**/*.ts'],
    languageOptions: { parser: tsParser, ecmaVersion: 'latest', sourceType: 'module' },
    rules: { 'no-restricted-syntax': ['error', ...selectors] },
  },
];
