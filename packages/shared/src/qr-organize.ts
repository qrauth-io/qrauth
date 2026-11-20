import { z } from "zod";

/**
 * Organising QR codes: search, tags and folders (Milestone 1).
 *
 * Tags are org-scoped labels, many per code. Folders are flat (no nesting),
 * at most one per code; a code without a folder is "unfiled".
 */

export const TAG_NAME_MAX = 32;
export const FOLDER_NAME_MAX = 64;
export const MAX_TAGS_PER_ORG = 100;
export const MAX_FOLDERS_PER_ORG = 200;
/** Codes per bulk tag or move request, the same cap as bulk revoke. */
export const MAX_BULK_ORGANIZE_TOKENS = 100;
/** Tags per bulk request and per list filter. */
export const MAX_TAGS_PER_REQUEST = 20;
export const SEARCH_QUERY_MAX = 100;
/** The `folderId` list filter value that selects codes without a folder. */
export const UNFILED_FOLDER = "unfiled";

/** The fixed tag palette. Clients map each key to a colour of their theme. */
export const TAG_COLORS = [
  "grey",
  "blue",
  "teal",
  "green",
  "yellow",
  "orange",
  "red",
  "pink",
  "purple",
] as const;
export type TagColor = (typeof TAG_COLORS)[number];

const tagName = z
  .string()
  .trim()
  .min(1, "Tag name is required")
  .max(TAG_NAME_MAX, `Tag name must be at most ${TAG_NAME_MAX} characters`);

const folderName = z
  .string()
  .trim()
  .min(1, "Folder name is required")
  .max(FOLDER_NAME_MAX, `Folder name must be at most ${FOLDER_NAME_MAX} characters`);

const resourceId = z.string().min(1).max(64);
const qrToken = z.string().min(1).max(64);

export const createTagSchema = z
  .object({ name: tagName, color: z.enum(TAG_COLORS).default("grey") })
  .strict();

export const updateTagSchema = z
  .object({ name: tagName.optional(), color: z.enum(TAG_COLORS).optional() })
  .strict()
  .refine((v) => v.name !== undefined || v.color !== undefined, {
    message: "Provide a name or a color",
  });

export const createFolderSchema = z.object({ name: folderName }).strict();
export const updateFolderSchema = createFolderSchema;

const tokenList = z
  .array(qrToken)
  .min(1, "Select at least one QR code")
  .max(MAX_BULK_ORGANIZE_TOKENS, `At most ${MAX_BULK_ORGANIZE_TOKENS} QR codes per request`);

/** Add and/or remove tags on up to 100 codes. A tag in both lists is refused. */
export const bulkTagSchema = z
  .object({
    tokens: tokenList,
    add: z.array(resourceId).max(MAX_TAGS_PER_REQUEST).default([]),
    remove: z.array(resourceId).max(MAX_TAGS_PER_REQUEST).default([]),
  })
  .strict()
  .refine((v) => v.add.length + v.remove.length > 0, { message: "Provide tags to add or remove" })
  .refine((v) => !v.add.some((id) => v.remove.includes(id)), {
    message: "A tag cannot be both added and removed",
  });

/** Move up to 100 codes into a folder, or out of any folder with `folderId: null`. */
export const bulkMoveSchema = z
  .object({ tokens: tokenList, folderId: resourceId.nullable() })
  .strict();

/** Comma-separated tag ids in a query string, e.g. `?tagIds=a,b`. */
const tagIdList = z
  .string()
  .transform((s) => [...new Set(s.split(",").map((id) => id.trim()).filter(Boolean))])
  .pipe(z.array(resourceId).max(MAX_TAGS_PER_REQUEST, `At most ${MAX_TAGS_PER_REQUEST} tags`));

/** Search and filter fields of `GET /api/v1/qrcodes`, next to page, pageSize and status. */
export const qrListFilterSchema = z.object({
  q: z.string().trim().max(SEARCH_QUERY_MAX).optional(),
  /** Content type key, matched exactly; keys are lower-case, so input is lower-cased. */
  contentType: z.string().trim().toLowerCase().min(1).max(32).optional(),
  /** Codes carrying at least one of these tags. */
  tagIds: tagIdList.optional(),
  /** A folder id, or `unfiled` for codes without a folder. */
  folderId: resourceId.optional(),
  /** `true`: only codes marked outside the organization's allowlist (ADR-0008 D8). */
  outsidePolicy: z.enum(["true", "false"]).transform((v) => v === "true").optional(),
});

export type CreateTagInput = z.infer<typeof createTagSchema>;
export type UpdateTagInput = z.infer<typeof updateTagSchema>;
export type CreateFolderInput = z.infer<typeof createFolderSchema>;
export type BulkTagInput = z.infer<typeof bulkTagSchema>;
export type BulkMoveInput = z.infer<typeof bulkMoveSchema>;
export type QrListFilter = z.infer<typeof qrListFilterSchema>;
