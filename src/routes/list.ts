/**
 * BUD-02: GET /list/:pubkey — List blobs uploaded by a pubkey
 *
 * This endpoint is optional and marked unrecommended by the BUD-02 spec.
 * It is disabled by default (list.enabled = false).
 *
 * Spec requirements:
 *   - Returns a JSON array of BlobDescriptors sorted by uploaded date DESC
 *   - Supports cursor-based pagination via `cursor` (sha256) and `limit` query params
 *   - Supports optional `since` / `until` Unix timestamp filters
 *   - Requires a BUD-11 list token signed by the listed pubkey: a list shows what
 *     a pubkey received and when it deleted it, so nobody else may read it
 */

import { Hono } from "@hono/hono";
import { HTTPException } from "@hono/hono/http-exception";
import type { Client } from "@libsql/client";
import { getMediaThumbnail, listBlobsByPubkey } from "../db/blobs.ts";
import { requireAuth } from "../middleware/auth.ts";
import type { BlossomVariables } from "../middleware/auth.ts";
import { errorResponse } from "../middleware/errors.ts";
import type { Config } from "../config/schema.ts";
import { type Nip94Tag, nip94Tags } from "../utils/nip94.ts";
import { getBaseUrl, getBlobUrl } from "../utils/url.ts";

/** 64-character lowercase hex string — valid Nostr pubkey format */
const HEX_PUBKEY_RE = /^[0-9a-f]{64}$/;

/** BUD-02 Blob Descriptor */
interface BlobDescriptor {
  url: string;
  sha256: string;
  size: number;
  type: string;
  uploaded: number;
  /** Additional NIP-94 file metadata tags. */
  nip94?: Nip94Tag[];
}

export function buildListRouter(
  db: Client,
  config: Config,
): Hono<{ Variables: BlossomVariables }> {
  const app = new Hono<{ Variables: BlossomVariables }>();

  app.get("/list/:pubkey", async (ctx) => {
    if (!config.list.enabled) {
      return errorResponse(
        ctx,
        404,
        "List endpoint is disabled on this server",
      );
    }

    let auth: ReturnType<typeof requireAuth>;
    try {
      auth = requireAuth(ctx, "list");
    } catch (err) {
      if (err instanceof HTTPException) {
        return errorResponse(ctx, err.status as 401 | 403, err.message);
      }
      throw err;
    }

    const pubkey = ctx.req.param("pubkey").toLowerCase();
    if (!HEX_PUBKEY_RE.test(pubkey)) {
      return errorResponse(
        ctx,
        400,
        "Invalid pubkey: must be a 64-character lowercase hex string",
      );
    }

    if (auth.pubkey !== pubkey) {
      return errorResponse(ctx, 403, "You may only list your own blobs");
    }

    const rawLimit = ctx.req.query("limit");
    const rawSince = ctx.req.query("since");
    const rawUntil = ctx.req.query("until");
    const cursor = ctx.req.query("cursor") ?? undefined;

    const limit = rawLimit !== undefined ? parseInt(rawLimit, 10) : undefined;
    if (limit !== undefined && (isNaN(limit) || limit < 1)) {
      return errorResponse(
        ctx,
        400,
        "Invalid limit: must be a positive integer",
      );
    }

    const since = rawSince !== undefined ? parseInt(rawSince, 10) : undefined;
    if (since !== undefined && isNaN(since)) {
      return errorResponse(ctx, 400, "Invalid since: must be a Unix timestamp");
    }

    const until = rawUntil !== undefined ? parseInt(rawUntil, 10) : undefined;
    if (until !== undefined && isNaN(until)) {
      return errorResponse(ctx, 400, "Invalid until: must be a Unix timestamp");
    }

    if (cursor !== undefined && !HEX_PUBKEY_RE.test(cursor)) {
      return errorResponse(
        ctx,
        400,
        "Invalid cursor: must be a 64-character sha256 hex string",
      );
    }

    const blobs = await listBlobsByPubkey(db, pubkey, {
      limit,
      cursor,
      since,
      until,
    });

    const baseUrl = getBaseUrl(ctx.req.raw, config.publicDomain);
    const descriptors: BlobDescriptor[] = await Promise.all(
      blobs.map(async (b) => {
        const url = getBlobUrl(b.sha256, b.type, baseUrl);
        const type = b.type ?? "application/octet-stream";
        const thumbnail = await getMediaThumbnail(db, b.sha256);
        const thumbnailTag: Nip94Tag | null = thumbnail
          ? [
            "thumb",
            getBlobUrl(thumbnail.sha256, thumbnail.type, baseUrl),
            thumbnail.sha256,
          ]
          : null;
        return {
          url,
          sha256: b.sha256,
          size: b.size,
          type,
          uploaded: b.uploaded,
          nip94: nip94Tags({
            url,
            sha256: b.sha256,
            size: b.size,
            type,
            tags: [...(b.nip94 ?? []), ...(thumbnailTag ? [thumbnailTag] : [])],
          }),
        };
      }),
    );

    return ctx.json(descriptors);
  });

  return app;
}
