/**
 * @qrauth/merkle-log — RFC 9162 Merkle tree hash, inclusion proofs and
 * consistency proofs (ADR-0009 D1; the Trust Records log uses sha256Hasher). Pure TypeScript; the only runtime
 * dependency is @noble/hashes.
 */
export { constantTimeEqual } from './bytes.js';
export { createHasher, sha256Hasher, sha3_256Hasher } from './hasher.js';
export type { HashFunction, MerkleHasher } from './hasher.js';
export { consistencyProof, inclusionProof, rootHash } from './tree.js';
export { verifyConsistency, verifyInclusion } from './verify.js';
export type { ConsistencyCheck, InclusionCheck } from './verify.js';
export {
  CheckpointError,
  TREE_HEAD_DOMAIN_PREFIX,
  TREE_HEAD_SIGNATURE_TYPE,
  TRUST_LOG_ORIGIN,
  checkpointNoteText,
  formatCheckpoint,
  parseCheckpoint,
  treeHeadKeyId,
  treeHeadMessage,
} from './checkpoint.js';
export type {
  CheckpointHead,
  CheckpointSignature,
  ParsedCheckpoint,
  SignedCheckpointHead,
  TreeHeadFields,
} from './checkpoint.js';
