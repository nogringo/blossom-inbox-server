/**
 * E2E tests for the draft BUD "blob pinning": p tags on PUT /upload, HEAD
 * /upload and PUT /mirror, PUT /pin/<sha256>, GET /pin/<sha256>, and pin
 * removal through DELETE /<sha256>.
 *
 * All tests share one DB, storage dir, and worker pool. sanitizeOps and
 * sanitizeResources are disabled because the pool's MessagePorts outlive
 * individual tests by design.
 */

import type { Client } from "@libsql/client";
import type { Hono } from "@hono/hono";
import { assert, assertEquals } from "@std/assert";
import { crypto as stdCrypto } from "@std/crypto";
import { encodeBase64Url } from "@std/encoding/base64url";
import { encodeHex } from "@std/encoding/hex";
import { join } from "@std/path";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { ConfigSchema } from "../../src/config/schema.ts";
import { initDb } from "../../src/db/client.ts";
import type { BlossomVariables } from "../../src/middleware/auth.ts";
import { buildApp } from "../../src/server.ts";
import { LocalStorage } from "../../src/storage/local.ts";
import { initPool } from "../../src/workers/pool.ts";

type App = Hono<{ Variables: BlossomVariables }>;

interface TestBlob {
  data: Uint8Array<ArrayBuffer>;
  hash: string;
}

const aliceSk = generateSecretKey();
const alicePk = getPublicKey(aliceSk);
const bobSk = generateSecretKey();
const bobPk = getPublicKey(bobSk);
const carolSk = generateSecretKey();
const carolPk = getPublicKey(carolSk);

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await stdCrypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return encodeHex(new Uint8Array(buf));
}

async function makeBlob(label: string): Promise<TestBlob> {
  const data = new TextEncoder().encode(`pin test ${label} ${crypto.randomUUID()}`);
  return { data, hash: await sha256Hex(data) };
}

function authHeader(sk: Uint8Array, verb: string, tags: string[][] = []): string {
  const now = Math.floor(Date.now() / 1000);
  const event = finalizeEvent(
    {
      kind: 24242,
      created_at: now,
      tags: [["t", verb], ["expiration", String(now + 600)], ...tags],
      content: "Pin test",
    },
    sk,
  );
  return `Nostr ${encodeBase64Url(new TextEncoder().encode(JSON.stringify(event)))}`;
}

function pTags(pubkeys: string[]): string[][] {
  return pubkeys.map((pubkey) => ["p", pubkey]);
}

function send(app: App, path: string, init?: RequestInit): Promise<Response> {
  return Promise.resolve(app.fetch(new Request(`http://localhost${path}`, init)));
}

function upload(
  app: App,
  blob: TestBlob,
  sk: Uint8Array,
  pinFor: string[] = [],
  contentType = "text/plain",
): Promise<Response> {
  return send(app, "/upload", {
    method: "PUT",
    headers: {
      "Content-Length": String(blob.data.byteLength),
      "Content-Type": contentType,
      "X-SHA-256": blob.hash,
      Authorization: authHeader(sk, "upload", [["x", blob.hash], ...pTags(pinFor)]),
    },
    body: blob.data,
  });
}

function putPin(app: App, hash: string, sk: Uint8Array, pinFor: string[] = []): Promise<Response> {
  return send(app, `/pin/${hash}`, {
    method: "PUT",
    headers: { Authorization: authHeader(sk, "pin", [["x", hash], ...pTags(pinFor)]) },
  });
}

function getPin(app: App, hash: string, sk: Uint8Array): Promise<Response> {
  return send(app, `/pin/${hash}`, {
    headers: { Authorization: authHeader(sk, "pin", [["x", hash]]) },
  });
}

function deleteAs(app: App, hash: string, sk: Uint8Array): Promise<Response> {
  return send(app, `/${hash}`, {
    method: "DELETE",
    headers: { Authorization: authHeader(sk, "delete", [["x", hash]]) },
  });
}

async function assertStatus(response: Promise<Response>, status: number): Promise<void> {
  const res = await response;
  await res.body?.cancel();
  assertEquals(res.status, status);
}

async function assertPinned(app: App, hash: string, sk: Uint8Array, pinned: boolean): Promise<void> {
  await assertStatus(getPin(app, hash, sk), pinned ? 200 : 404);
}

let db: Client;
let openApp: App;
let inboxApp: App;
let uploadsDisabledApp: App;
let cleanup: () => Promise<void>;

const testOpts = { sanitizeOps: false, sanitizeResources: false } as const;

Deno.test({
  name: "pin e2e setup: initialize shared servers",
  async fn() {
    const tmpDir = await Deno.makeTempDir({ prefix: "blossom_e2e_pin_" });
    const dbConfig = { path: join(tmpDir, "test.db") };
    db = await initDb(dbConfig);
    const storage = new LocalStorage(join(tmpDir, "blobs"));
    await storage.setup();
    const pool = initPool(1, 4, 500, db, dbConfig);

    openApp = await buildApp(
      db,
      storage,
      ConfigSchema.parse({
        publicDomain: "localhost",
        storage: { rules: [{ type: "*", expiration: "1 month" }] },
      }),
    );
    // Only Bob may hold blobs, so it acts as Bob's inbox.
    inboxApp = await buildApp(
      db,
      storage,
      ConfigSchema.parse({
        publicDomain: "localhost",
        upload: { requirePubkeyInRule: true },
        storage: { rules: [{ type: "text/*", expiration: "1 year", pubkeys: [bobPk] }] },
      }),
    );
    uploadsDisabledApp = await buildApp(
      db,
      storage,
      ConfigSchema.parse({ publicDomain: "localhost", upload: { enabled: false } }),
    );

    cleanup = async () => {
      pool.shutdown();
      db.close();
      await Deno.remove(tmpDir, { recursive: true });
    };
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /upload: without p tags pins the blob for the signer",
  async fn() {
    const blob = await makeBlob("signer");
    const before = Math.floor(Date.now() / 1000);
    await assertStatus(upload(openApp, blob, aliceSk), 201);

    const res = await getPin(openApp, blob.hash, aliceSk);
    assertEquals(res.status, 200);
    const pin = await res.json() as { sha256: string; pinned: number };
    assertEquals(pin.sha256, blob.hash);
    assert(pin.pinned >= before && pin.pinned <= Math.floor(Date.now() / 1000));
    assertEquals(Object.keys(pin).sort(), ["pinned", "sha256"]);

    await assertPinned(openApp, blob.hash, bobSk, false);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /upload: p tags pin for each p pubkey and not for the signer",
  async fn() {
    const blob = await makeBlob("recipients");
    const oneTimeSk = generateSecretKey();
    await assertStatus(upload(openApp, blob, oneTimeSk, [bobPk, carolPk, bobPk]), 201);

    await assertPinned(openApp, blob.hash, bobSk, true);
    await assertPinned(openApp, blob.hash, carolSk, true);
    await assertPinned(openApp, blob.hash, oneTimeSk, false);
    await assertStatus(deleteAs(openApp, blob.hash, oneTimeSk), 403);
  },
  ...testOpts,
});

Deno.test({
  name: "DELETE: each pubkey removes its own pin and the blob goes with the last one",
  async fn() {
    const blob = await makeBlob("delete");
    await assertStatus(upload(openApp, blob, generateSecretKey(), [bobPk, carolPk]), 201);

    await assertStatus(deleteAs(openApp, blob.hash, bobSk), 204);
    await assertPinned(openApp, blob.hash, bobSk, false);
    await assertStatus(send(openApp, `/${blob.hash}`), 200);

    await assertStatus(deleteAs(openApp, blob.hash, carolSk), 204);
    await assertStatus(send(openApp, `/${blob.hash}`), 404);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /upload: malformed p tags return 400 and store nothing",
  async fn() {
    for (const value of ["npub1notahexkey", bobPk.toUpperCase(), bobPk.slice(2), ""]) {
      const blob = await makeBlob(`malformed ${value}`);
      await assertStatus(upload(openApp, blob, aliceSk, [value]), 400);
      await assertStatus(send(openApp, `/${blob.hash}`, { method: "HEAD" }), 404);
    }
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /upload: dedup hit pins the stored blob for the p pubkeys",
  async fn() {
    const blob = await makeBlob("dedup");
    await assertStatus(upload(openApp, blob, aliceSk), 201);
    await assertStatus(upload(openApp, blob, generateSecretKey(), [bobPk]), 200);

    await assertPinned(openApp, blob.hash, bobSk, true);
    await assertPinned(openApp, blob.hash, aliceSk, true);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /upload: storage rules apply to the p pubkeys instead of the signer",
  async fn() {
    const forBob = await makeBlob("inbox bob");
    await assertStatus(upload(inboxApp, forBob, generateSecretKey(), [bobPk]), 201);
    await assertPinned(inboxApp, forBob.hash, bobSk, true);

    const forCarol = await makeBlob("inbox carol");
    await assertStatus(upload(inboxApp, forCarol, generateSecretKey(), [carolPk]), 403);
    await assertStatus(upload(inboxApp, forCarol, generateSecretKey(), [bobPk, carolPk]), 403);
    await assertStatus(send(inboxApp, `/${forCarol.hash}`, { method: "HEAD" }), 404);

    const unsupported = await makeBlob("inbox png");
    await assertStatus(upload(inboxApp, unsupported, generateSecretKey(), [bobPk], "image/png"), 415);

    // Without p tags the signer must still be allowlisted itself.
    await assertStatus(upload(inboxApp, await makeBlob("stranger"), generateSecretKey()), 401);
  },
  ...testOpts,
});

Deno.test({
  name: "HEAD /upload: answers for p tags as PUT /upload would",
  async fn() {
    const blob = await makeBlob("preflight");
    const preflight = (pinFor: string[]) =>
      send(inboxApp, "/upload", {
        method: "HEAD",
        headers: {
          "X-Content-Type": "text/plain",
          "X-Content-Length": String(blob.data.byteLength),
          "X-SHA-256": blob.hash,
          Authorization: authHeader(generateSecretKey(), "upload", [["x", blob.hash], ...pTags(pinFor)]),
        },
      });

    await assertStatus(preflight([bobPk]), 200);
    await assertStatus(preflight([carolPk]), 403);
    await assertStatus(preflight([bobPk, carolPk]), 403);
    await assertStatus(preflight(["not-a-pubkey"]), 400);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /pin: pins a stored blob for the signer and returns its descriptor",
  async fn() {
    const blob = await makeBlob("pin signer");
    await assertStatus(upload(openApp, blob, aliceSk), 201);

    const res = await putPin(openApp, blob.hash, bobSk);
    assertEquals(res.status, 200);
    const descriptor = await res.json() as Record<string, unknown>;
    assertEquals(descriptor.sha256, blob.hash);
    assertEquals(descriptor.size, blob.data.byteLength);
    assertEquals(descriptor.type, "text/plain");
    assertEquals(descriptor.url, `http://localhost/${blob.hash}.txt`);

    await assertPinned(openApp, blob.hash, bobSk, true);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /pin: p tags pin for the p pubkeys and not for the signer",
  async fn() {
    const blob = await makeBlob("pin recipients");
    await assertStatus(upload(openApp, blob, aliceSk), 201);
    const oneTimeSk = generateSecretKey();

    await assertStatus(putPin(openApp, blob.hash, oneTimeSk, [carolPk]), 200);
    await assertPinned(openApp, blob.hash, carolSk, true);
    await assertPinned(openApp, blob.hash, oneTimeSk, false);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /pin: re-pinning keeps the original pin date and refreshes the access time",
  async fn() {
    const blob = await makeBlob("repin");
    await assertStatus(upload(openApp, blob, aliceSk), 201);
    await db.execute({ sql: "UPDATE owners SET pinned = 1000 WHERE blob = ? AND pubkey = ?", args: [blob.hash, alicePk] });
    await db.execute({ sql: "UPDATE accessed SET timestamp = 1000 WHERE blob = ?", args: [blob.hash] });

    const before = Math.floor(Date.now() / 1000);
    await assertStatus(putPin(openApp, blob.hash, aliceSk), 200);

    const res = await getPin(openApp, blob.hash, aliceSk);
    assertEquals(await res.json(), { sha256: blob.hash, pinned: 1000 });
    const accessed = await db.execute({ sql: "SELECT timestamp FROM accessed WHERE blob = ?", args: [blob.hash] });
    assert((accessed.rows[0][0] as number) >= before);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /pin: rejects bad requests with the matching status",
  async fn() {
    const blob = await makeBlob("pin status");
    await assertStatus(upload(openApp, blob, aliceSk), 201);
    const pinPath = `/pin/${blob.hash}`;

    await assertStatus(send(openApp, pinPath, { method: "PUT" }), 401);
    await assertStatus(
      send(openApp, pinPath, { method: "PUT", headers: { Authorization: authHeader(bobSk, "upload", [["x", blob.hash]]) } }),
      403,
    );
    await assertStatus(
      send(openApp, pinPath, { method: "PUT", headers: { Authorization: authHeader(bobSk, "pin") } }),
      403,
    );
    await assertStatus(putPin(openApp, "f".repeat(64), bobSk), 404);
    await assertStatus(putPin(openApp, "not-a-hash", bobSk), 400);
    await assertStatus(putPin(openApp, blob.hash, bobSk, ["npub1notahexkey"]), 400);
    await assertStatus(putPin(uploadsDisabledApp, blob.hash, bobSk), 403);

    await assertPinned(openApp, blob.hash, bobSk, false);
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /pin: storage rules refuse pins for pubkeys they do not accept",
  async fn() {
    const blob = await makeBlob("pin inbox");
    await assertStatus(upload(inboxApp, blob, bobSk), 201);

    await assertStatus(putPin(inboxApp, blob.hash, carolSk), 403);
    await assertStatus(putPin(inboxApp, blob.hash, generateSecretKey(), [carolPk]), 403);
    await assertPinned(inboxApp, blob.hash, carolSk, false);
  },
  ...testOpts,
});

Deno.test({
  name: "GET /pin: rejects bad requests and never reveals other pins",
  async fn() {
    const blob = await makeBlob("get pin");
    await assertStatus(upload(openApp, blob, aliceSk), 201);
    const pinPath = `/pin/${blob.hash}`;

    await assertStatus(send(openApp, pinPath), 401);
    await assertStatus(send(openApp, pinPath, { headers: { Authorization: authHeader(aliceSk, "get", [["x", blob.hash]]) } }), 403);
    await assertStatus(send(openApp, pinPath, { headers: { Authorization: authHeader(aliceSk, "pin") } }), 403);
    await assertStatus(getPin(openApp, "not-a-hash", aliceSk), 400);
    await assertPinned(openApp, blob.hash, bobSk, false);
    await assertPinned(openApp, "e".repeat(64), aliceSk, false);
  },
  ...testOpts,
});

Deno.test({
  name: "GET /pin: owners recorded before pin dates existed report the upload time",
  async fn() {
    const blob = await makeBlob("legacy");
    const uploadRes = await upload(openApp, blob, aliceSk);
    const { uploaded } = await uploadRes.json() as { uploaded: number };
    await db.execute({ sql: "UPDATE owners SET pinned = NULL WHERE blob = ?", args: [blob.hash] });

    const res = await getPin(openApp, blob.hash, aliceSk);
    assertEquals(await res.json(), { sha256: blob.hash, pinned: uploaded });
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /mirror: p tags pin the mirrored blob for the p pubkeys",
  async fn() {
    const blob = await makeBlob("mirror");
    const originalFetch = globalThis.fetch;
    globalThis.fetch = () => Promise.resolve(new Response(blob.data, { headers: { "Content-Type": "text/plain" } }));

    try {
      const oneTimeSk = generateSecretKey();
      await assertStatus(
        send(openApp, "/mirror", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            Authorization: authHeader(oneTimeSk, "upload", [["x", blob.hash], ["p", bobPk]]),
          },
          body: JSON.stringify({ url: "https://1.1.1.1/blob" }),
        }),
        200,
      );
      await assertPinned(openApp, blob.hash, bobSk, true);
      await assertPinned(openApp, blob.hash, oneTimeSk, false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  },
  ...testOpts,
});

Deno.test({
  name: "PUT /mirror: a refused p pubkey is rejected before the origin fetch",
  async fn() {
    let originHits = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = () => {
      originHits++;
      return Promise.resolve(new Response("unused", { headers: { "Content-Type": "text/plain" } }));
    };

    try {
      await assertStatus(
        send(inboxApp, "/mirror", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            Authorization: authHeader(generateSecretKey(), "upload", [["p", carolPk]]),
          },
          body: JSON.stringify({ url: "https://1.1.1.1/blob" }),
        }),
        403,
      );
      assertEquals(originHits, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  },
  ...testOpts,
});

Deno.test({
  name: "pin e2e teardown: shutdown shared servers",
  async fn() {
    await cleanup();
  },
  ...testOpts,
});
