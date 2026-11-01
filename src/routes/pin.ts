/**
 * Draft BUD "blob pinning":
 *   PUT /pin/:sha256: pin a blob the signer already pins, for itself or its p pubkeys
 *   GET /pin/:sha256: read the signer's own pin on a blob
 *
 * A pin is an owner row. A pubkey removes its pin with DELETE /:sha256
 * (BUD-12), which purges the blob once nobody pins it anymore.
 *
 * A signer that does not pin the blob gets the same 404 as for a missing one.
 * Otherwise anyone who knows a hash could learn whether it is stored, and pin
 * it for itself to read it.
 */

import { Hono } from "@hono/hono";
import type { Client } from "@libsql/client";
import { getBlob, getPinned, isOwner, pinBlob } from "../db/blobs.ts";
import { getPinTargets, requireAuth, requireXTag } from "../middleware/auth.ts";
import type { BlossomVariables } from "../middleware/auth.ts";
import { errorResponse } from "../middleware/errors.ts";
import type { Config } from "../config/schema.ts";
import { findRefusedPubkey } from "../prune/rules.ts";
import { type Nip94Tag, nip94Tags } from "../utils/nip94.ts";
import { getBaseUrl, getBlobUrl } from "../utils/url.ts";

const SHA256_RE = /^[0-9a-f]{64}$/;

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

export function buildPinRouter(
  db: Client,
  config: Config,
): Hono<{ Variables: BlossomVariables }> {
  const app = new Hono<{ Variables: BlossomVariables }>();

  app.put("/pin/:sha256", async (ctx) => {
    if (!config.upload.enabled) {
      return errorResponse(ctx, 403, "Pinning is disabled on this server");
    }

    const sha256 = ctx.req.param("sha256");
    if (!SHA256_RE.test(sha256)) {
      return errorResponse(ctx, 400, "Invalid sha256 hash");
    }

    const auth = requireAuth(ctx, "pin");
    requireXTag(auth, sha256);
    const pinTargets = getPinTargets(auth);
    const pinners = pinTargets.length > 0 ? pinTargets : [auth.pubkey];

    if (!(await isOwner(db, sha256, auth.pubkey))) {
      return errorResponse(ctx, 404, "Blob not found");
    }
    const blob = await getBlob(db, sha256);
    if (!blob) {
      return errorResponse(ctx, 404, "Blob not found");
    }

    const refusedPubkey = findRefusedPubkey(
      blob.type,
      pinners,
      config.storage.rules,
      config.upload.requirePubkeyInRule,
    );
    if (refusedPubkey) {
      return errorResponse(ctx, 403, `Server refuses to pin this blob for ${refusedPubkey}`);
    }

    await pinBlob(db, sha256, pinners, Math.floor(Date.now() / 1000));

    const baseUrl = getBaseUrl(ctx.req.raw, config.publicDomain);
    const url = getBlobUrl(blob.sha256, blob.type, baseUrl);
    const type = blob.type ?? "application/octet-stream";
    return ctx.json(
      {
        url,
        sha256: blob.sha256,
        size: blob.size,
        type,
        uploaded: blob.uploaded,
        nip94: nip94Tags({
          url,
          sha256: blob.sha256,
          size: blob.size,
          type,
          tags: blob.nip94,
        }),
      } satisfies BlobDescriptor,
    );
  });

  app.get("/pin/:sha256", async (ctx) => {
    const sha256 = ctx.req.param("sha256");
    if (!SHA256_RE.test(sha256)) {
      return errorResponse(ctx, 400, "Invalid sha256 hash");
    }

    const auth = requireAuth(ctx, "pin");
    requireXTag(auth, sha256);

    const pinned = await getPinned(db, sha256, auth.pubkey);
    if (pinned === null) {
      return errorResponse(ctx, 404, "Blob is not pinned by this pubkey");
    }
    return ctx.json({ sha256, pinned });
  });

  return app;
}
