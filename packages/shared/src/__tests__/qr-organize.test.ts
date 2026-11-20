import { describe, expect, it } from 'vitest';

import {
  bulkMoveSchema,
  bulkTagSchema,
  createTagSchema,
  qrListFilterSchema,
  updateTagSchema,
  MAX_BULK_ORGANIZE_TOKENS,
  MAX_TAGS_PER_REQUEST,
  TAG_COLORS,
} from '../qr-organize.js';

describe('createTagSchema', () => {
  it('trims the name and defaults the colour to grey', () => {
    expect(createTagSchema.parse({ name: '  Promo ' })).toEqual({ name: 'Promo', color: 'grey' });
  });

  it('accepts 32 characters and refuses 33, blank names and unknown colours or fields', () => {
    expect(createTagSchema.safeParse({ name: 'x'.repeat(32) }).success).toBe(true);
    expect(createTagSchema.safeParse({ name: 'x'.repeat(33) }).success).toBe(false);
    expect(createTagSchema.safeParse({ name: '   ' }).success).toBe(false);
    expect(createTagSchema.safeParse({ name: 'a', color: '#ff0000' }).success).toBe(false);
    expect(createTagSchema.safeParse({ name: 'a', organizationId: 'x' }).success).toBe(false);
  });

  it('accepts every palette colour', () => {
    for (const color of TAG_COLORS) expect(createTagSchema.safeParse({ name: 'a', color }).success).toBe(true);
  });
});

describe('updateTagSchema', () => {
  it('needs a name or a colour', () => {
    expect(updateTagSchema.safeParse({}).success).toBe(false);
    expect(updateTagSchema.safeParse({ color: 'red' }).success).toBe(true);
  });
});

describe('bulkTagSchema', () => {
  it('needs at least one tag to add or remove and refuses a tag in both lists', () => {
    expect(bulkTagSchema.safeParse({ tokens: ['a'] }).success).toBe(false);
    expect(bulkTagSchema.safeParse({ tokens: ['a'], add: ['t'], remove: ['t'] }).success).toBe(false);
    expect(bulkTagSchema.parse({ tokens: ['a'], remove: ['t'] })).toEqual({ tokens: ['a'], add: [], remove: ['t'] });
  });

  it(`caps tokens at ${MAX_BULK_ORGANIZE_TOKENS} and tags at ${MAX_TAGS_PER_REQUEST}`, () => {
    const tokens = (n: number) => Array.from({ length: n }, (_, i) => `t${i}`);
    expect(bulkTagSchema.safeParse({ tokens: tokens(MAX_BULK_ORGANIZE_TOKENS), add: ['x'] }).success).toBe(true);
    expect(bulkTagSchema.safeParse({ tokens: tokens(MAX_BULK_ORGANIZE_TOKENS + 1), add: ['x'] }).success).toBe(false);
    expect(bulkTagSchema.safeParse({ tokens: ['a'], add: tokens(MAX_TAGS_PER_REQUEST + 1) }).success).toBe(false);
    expect(bulkTagSchema.safeParse({ tokens: [], add: ['x'] }).success).toBe(false);
  });
});

describe('bulkMoveSchema', () => {
  it('takes a folder id or null for unfiled, and nothing else', () => {
    expect(bulkMoveSchema.safeParse({ tokens: ['a'], folderId: null }).success).toBe(true);
    expect(bulkMoveSchema.safeParse({ tokens: ['a'], folderId: 'f1' }).success).toBe(true);
    expect(bulkMoveSchema.safeParse({ tokens: ['a'] }).success).toBe(false);
  });
});

describe('qrListFilterSchema', () => {
  it('splits, trims and de-duplicates comma-separated tag ids', () => {
    expect(qrListFilterSchema.parse({ tagIds: 'a, b,,a' }).tagIds).toEqual(['a', 'b']);
  });

  it('trims q and refuses over-long queries and too many tags', () => {
    expect(qrListFilterSchema.parse({ q: '  shop ' }).q).toBe('shop');
    expect(qrListFilterSchema.safeParse({ q: 'x'.repeat(101) }).success).toBe(false);
    const ids = Array.from({ length: MAX_TAGS_PER_REQUEST + 1 }, (_, i) => `t${i}`).join(',');
    expect(qrListFilterSchema.safeParse({ tagIds: ids }).success).toBe(false);
  });
});
