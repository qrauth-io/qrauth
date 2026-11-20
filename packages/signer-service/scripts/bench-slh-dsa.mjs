#!/usr/bin/env node
// SLH-DSA-SHA2-128s signing benchmark: built-in (Node 24 / OpenSSL 3.5)
// vs @noble/post-quantum (pure JS). Not run in CI.
//
//   npm run build -w @qrauth/signer-service
//   node packages/signer-service/scripts/bench-slh-dsa.mjs [count]
//
// Uses only the public self-test key; touches no service or key file.
import {
  benchmarkSignatures,
  isNativeSlhDsaAvailable,
  nativeImplementation,
  nobleImplementation,
} from '../dist/slh-dsa.js';

const count = Math.max(1, Math.min(50, Number.parseInt(process.argv[2] ?? '5', 10) || 5));
const summary = (ms) => {
  const sorted = [...ms].sort((a, b) => a - b);
  return `median ${sorted[Math.floor(sorted.length / 2)]} ms, min ${sorted[0]}, max ${sorted.at(-1)}  [${ms.join(', ')}]`;
};

console.log(`node ${process.versions.node}, openssl ${process.versions.openssl}, ${count} signatures each`);
if (isNativeSlhDsaAvailable()) {
  console.log(`native: ${summary(benchmarkSignatures(nativeImplementation, count))}`);
} else {
  console.log('native: not available on this Node build');
}
console.log(`noble:  ${summary(benchmarkSignatures(nobleImplementation, count))}`);
