/**
 * One-shot application boundary for the fresh, invented bootstrap actor.
 * This wraps the real Express parser/router, but does NOT establish resource
 * ownership, start a listener, import the application, or authorize a launch.
 * The future owned HTTPS entrypoint must supply fresh issuer/key/source bytes,
 * await appReady, and stop the actual application/DB resources separately.
 */
import express, { Request, Response, RequestHandler } from "express";
import { createHash, createPublicKey, verify } from "node:crypto";
import { isProxy } from "node:util/types";
import { TLSSocket } from "node:tls";
import {
  markFncpSensitiveRequest,
  runInFncpLogBoundary,
} from "./fncp-log-boundary";

const SEED_SHA =
  "b8c49ddaab72740df997b4975e84b0a51501fa97e1c622420826f4840bc6e06b";
const AUDIENCE = "fncp-fresh-synthetic-bootstrap";
const CREATE = {
  topic: "FNCP Option C fresh disposable access QA",
  description: "Synthetic local test only. No genuine participant data.",
  is_active: true,
  is_anon: true,
  is_draft: false,
  is_data_open: false,
  topics_enabled: false,
  treevite_enabled: false,
  strict_moderation: true,
  profanity_filter: false,
  spam_filter: false,
};
const CLOSED = {
  is_active: false,
  use_xid_whitelist: true,
  xid_required: true,
  send_created_email: false,
};
const fail = () => new Error("Fresh bootstrap admission denied");
const hash = (value: string | Buffer) =>
  createHash("sha256").update(value).digest("hex");
const plain = (value: unknown): value is Record<string, any> =>
  !!value &&
  typeof value === "object" &&
  !isProxy(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
function exact(value: unknown, keys: string[]): Record<string, any> {
  if (!plain(value) || Reflect.ownKeys(value).length !== keys.length)
    throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (keys.some((key) => !fields[key] || !Object.hasOwn(fields[key], "value")))
    throw fail();
  return Object.fromEntries(keys.map((key) => [key, fields[key].value]));
}
function canonical(text: string) {
  const value = JSON.parse(text);
  if (JSON.stringify(value) !== text) throw fail();
  return value;
}
function segment(text: string) {
  if (!/^[A-Za-z0-9_-]+$/u.test(text)) throw fail();
  const bytes = Buffer.from(text, "base64url");
  if (bytes.toString("base64url") !== text) throw fail();
  return bytes;
}
function utf8(bytes: Buffer) {
  const text = bytes.toString("utf8");
  if (!Buffer.from(text).equals(bytes)) throw fail();
  return text;
}
const integer = (n: unknown): n is number =>
  Number.isSafeInteger(n) &&
  Number(n) >= 0 &&
  Number(n) <= 2147483647 &&
  !Object.is(n, -0);
const conversation = (id: unknown): id is string =>
  typeof id === "string" &&
  /^[0-9][0-9A-Za-z]{5,99}$/u.test(id) &&
  !/^9fncpBootstrap[0-9a-f]{48}$/u.test(id);

export function createFreshBootstrapAdmission(options: {
  issuer: string;
  publicJwk: Record<string, unknown>;
  seedStatementsJson: string;
}) {
  let issuer: string,
    seeds: string[],
    publicKey: ReturnType<typeof createPublicKey>,
    kid: string;
  try {
    if (arguments.length !== 1) throw fail();
    const input = exact(options, ["issuer", "publicJwk", "seedStatementsJson"]);
    issuer = input.issuer;
    if (
      typeof issuer !== "string" ||
      !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}\/$/u.test(issuer)
    )
      throw fail();
    const url = new URL(issuer);
    if (
      Number(url.port) < 1024 ||
      Number(url.port) > 65535 ||
      url.href !== issuer
    )
      throw fail();
    const jwk = exact(input.publicJwk, ["kty", "n", "e", "kid", "use", "alg"]);
    if (
      jwk.kty !== "RSA" ||
      jwk.e !== "AQAB" ||
      jwk.use !== "sig" ||
      jwk.alg !== "RS256" ||
      typeof jwk.n !== "string" ||
      segment(jwk.n).length !== 256 ||
      typeof jwk.kid !== "string" ||
      !/^[a-f0-9]{64}$/u.test(jwk.kid)
    )
      throw fail();
    publicKey = createPublicKey({ key: jwk, format: "jwk" });
    if (
      publicKey.asymmetricKeyType !== "rsa" ||
      publicKey.asymmetricKeyDetails?.modulusLength !== 2048 ||
      hash(publicKey.export({ type: "spki", format: "der" })) !== jwk.kid
    )
      throw fail();
    kid = jwk.kid;
    if (
      typeof input.seedStatementsJson !== "string" ||
      Buffer.byteLength(input.seedStatementsJson) > 16384 ||
      hash(input.seedStatementsJson) !== SEED_SHA
    )
      throw fail();
    seeds = JSON.parse(input.seedStatementsJson);
    if (
      !Array.isArray(seeds) ||
      seeds.length !== 15 ||
      seeds.some((s) => typeof s !== "string" || !s || s.length > 1000) ||
      new Set(seeds).size !== 15
    )
      throw fail();
    Object.freeze(seeds);
  } catch {
    throw fail();
  }

  let denied = false,
    busy = false,
    completed = 0,
    tokenHash: string | undefined;
  let conversationId: string | undefined, ownerPid: number | undefined;
  const ids: number[] = [];
  const started = performance.now();
  const wallStarted = Date.now();
  const active = new Set<Response>();
  const usable = () => {
    const elapsed = performance.now() - started;
    return (
      !denied &&
      completed < 19 &&
      Number.isFinite(elapsed) &&
      elapsed >= 0 &&
      elapsed < 120000
    );
  };
  function close() {
    denied = true;
    clearTimeout(lifetime);
    for (const res of active) res.destroy();
  }
  const lifetime = setTimeout(close, 120000);
  lifetime.unref();
  function authenticate(token: string) {
    if (token.length > 4096) throw fail();
    const parts = token.split(".");
    if (parts.length !== 3) throw fail();
    const header = exact(canonical(utf8(segment(parts[0]))), [
      "alg",
      "typ",
      "kid",
    ]);
    if (header.alg !== "RS256" || header.typ !== "JWT" || header.kid !== kid)
      throw fail();
    const claims = exact(canonical(utf8(segment(parts[1]))), [
      "iss",
      "aud",
      "sub",
      "email",
      "email_verified",
      "name",
      "iat",
      "nbf",
      "exp",
      "jti",
    ]);
    const now = Math.floor(Date.now() / 1000);
    if (
      !Number.isSafeInteger(now) ||
      Date.now() < wallStarted ||
      claims.iss !== issuer ||
      claims.aud !== AUDIENCE ||
      typeof claims.sub !== "string" ||
      !/^fncp-invented-bootstrap-admin-[a-f0-9]{48}$/u.test(claims.sub) ||
      claims.email !== "bootstrap-admin@bootstrap.example.invalid" ||
      claims.email_verified !== false ||
      claims.name !== "Invented local bootstrap administrator" ||
      typeof claims.jti !== "string" ||
      !/^[a-f0-9]{48}$/u.test(claims.jti) ||
      ![claims.iat, claims.nbf, claims.exp].every(Number.isSafeInteger) ||
      claims.nbf !== claims.iat ||
      claims.iat > now ||
      claims.exp <= now ||
      claims.exp <= claims.iat ||
      claims.exp - claims.iat > 120 ||
      !verify(
        "RSA-SHA256",
        Buffer.from(parts[0] + "." + parts[1]),
        publicKey,
        segment(parts[2])
      )
    )
      throw fail();
    const digest = hash(token);
    if (tokenHash && tokenHash !== digest) throw fail();
    tokenHash = digest;
  }
  function expected() {
    if (completed === 0)
      return { method: "POST", path: "/api/v3/conversations", body: CREATE };
    if (!conversationId) throw fail();
    if (completed < 16)
      return {
        method: "POST",
        path: "/api/v3/comments",
        body: {
          conversation_id: conversationId,
          txt: seeds[completed - 1],
          is_seed: true,
        },
      };
    if (completed === 16)
      return {
        method: "GET",
        path: `/api/v3/comments?conversation_id=${conversationId}&moderation=true&include_voting_patterns=true`,
        body: null,
      };
    if (completed === 17)
      return {
        method: "PUT",
        path: "/api/v3/conversations",
        body: { conversation_id: conversationId, ...CLOSED },
      };
    return {
      method: "GET",
      path: `/api/v3/conversations?conversation_id=${conversationId}`,
      body: null,
    };
  }
  function validateResponse(value: unknown) {
    if (completed === 0) {
      if (!plain(value) || !conversation(value.conversation_id)) throw fail();
      conversationId = value.conversation_id;
    } else if (completed < 16) {
      if (
        !plain(value) ||
        !integer(value.tid) ||
        !integer(value.currentPid) ||
        ids.includes(value.tid) ||
        (ownerPid !== undefined && ownerPid !== value.currentPid)
      )
        throw fail();
      ids.push(value.tid);
      ownerPid = value.currentPid;
    } else if (completed === 16) {
      if (
        !Array.isArray(value) ||
        value.length !== 15 ||
        new Set(value.map((row) => row?.tid)).size !== 15
      )
        throw fail();
      for (let index = 0; index < 15; index++) {
        const row = value.find((row) => row?.tid === ids[index]);
        if (
          !plain(row) ||
          row.conversation_id !== conversationId ||
          row.pid !== ownerPid ||
          row.txt !== seeds[index] ||
          row.is_seed !== true ||
          row.mod !== 1 ||
          row.active !== true ||
          row.agree_count !== 0 ||
          row.disagree_count !== 0 ||
          row.pass_count !== 1 ||
          row.count !== 1
        )
          throw fail();
      }
    } else {
      if (!plain(value) || value.conversation_id !== conversationId)
        throw fail();
      if (
        completed === 18 &&
        (value.is_owner !== true ||
          value.is_active !== false ||
          value.use_xid_whitelist !== true ||
          value.xid_required !== true ||
          value.is_data_open !== false ||
          value.strict_moderation !== true ||
          value.is_anon !== true ||
          value.is_draft !== false ||
          [
            "topics_enabled",
            "treevite_enabled",
            "profanity_filter",
            "spam_filter",
          ].some((key) => value[key] !== false))
      )
        throw fail();
    }
  }

  const router = express.Router({ caseSensitive: true, strict: true });
  router.use((req: Request, res: Response, next) => {
    markFncpSensitiveRequest(req);
    runInFncpLogBoundary(() => {
      try {
        if (
          !usable() ||
          busy ||
          req.httpVersion !== "1.1" ||
          !(req.socket as TLSSocket).encrypted ||
          req.socket.localAddress !== "127.0.0.1" ||
          req.socket.remoteAddress !== "127.0.0.1"
        )
          throw fail();
        const target = expected();
        if (req.method !== target.method || req.url !== target.path)
          throw fail();
        if (
          req.rawHeaders.reduce(
            (size, value) => size + Buffer.byteLength(value),
            0
          ) > 8192
        )
          throw fail();
        const headers = new Map<string, string>();
        for (let index = 0; index < req.rawHeaders.length; index += 2) {
          const name = req.rawHeaders[index].toLowerCase();
          if (headers.has(name)) throw fail();
          headers.set(name, req.rawHeaders[index + 1]);
        }
        const wanted = [
          "accept",
          "content-type",
          "x-forwarded-proto",
          "host",
          "connection",
          "authorization",
        ];
        if (target.body) wanted.push("content-length");
        if (
          headers.size !== wanted.length ||
          wanted.some((name) => !headers.has(name)) ||
          headers.get("accept") !== "application/json" ||
          headers.get("content-type") !== "application/json" ||
          headers.get("x-forwarded-proto") !== "https" ||
          headers.get("host") !== `127.0.0.1:${req.socket.localPort}` ||
          headers.get("connection") !== "close"
        )
          throw fail();
        const auth = headers.get("authorization");
        if (!auth.startsWith("Bearer ")) throw fail();
        authenticate(auth.slice(7));
        const length = target.body
          ? Buffer.byteLength(JSON.stringify(target.body))
          : 0;
        if (target.body && headers.get("content-length") !== String(length))
          throw fail();
        busy = true;
        active.add(res);
        const timer = setTimeout(close, 2000);
        timer.unref();
        let ended = false,
          responseValid = false,
          responseBytes = 0;
        const chunks: Buffer[] = [];
        const originalEnd = res.end.bind(res);
        const originalWriteHead = res.writeHead.bind(res);
        const capture = (chunk: any, encoding?: BufferEncoding) => {
          if (chunk === undefined || chunk === null) return;
          if (
            typeof chunk !== "string" &&
            !Buffer.isBuffer(chunk) &&
            !(chunk instanceof Uint8Array)
          )
            throw fail();
          const bytes = Buffer.isBuffer(chunk)
            ? chunk
            : typeof chunk === "string"
            ? Buffer.from(chunk, encoding)
            : Buffer.from(chunk);
          responseBytes += bytes.length;
          if (responseBytes > 65536) throw fail();
          chunks.push(bytes);
        };
        res.write = ((chunk: any, encoding?: any, callback?: any) => {
          try {
            if (!usable() || ended) throw fail();
            capture(
              chunk,
              typeof encoding === "string"
                ? (encoding as BufferEncoding)
                : undefined
            );
            const cb = typeof encoding === "function" ? encoding : callback;
            if (cb) queueMicrotask(() => cb());
            return true;
          } catch {
            close();
            return false;
          }
        }) as typeof res.write;
        res.end = ((chunk?: any, encoding?: any, callback?: any) => {
          try {
            if (!usable() || ended) throw fail();
            ended = true;
            if (typeof chunk !== "function")
              capture(
                chunk,
                typeof encoding === "string"
                  ? (encoding as BufferEncoding)
                  : undefined
              );
            const type = res.getHeader("content-type");
            if (
              res.statusCode !== 200 ||
              typeof type !== "string" ||
              !/^application\/json(?:; charset=utf-8)?$/u.test(type) ||
              res.hasHeader("location") ||
              res.hasHeader("content-encoding") ||
              res.hasHeader("set-cookie") ||
              res.headersSent
            )
              throw fail();
            const bytes = Buffer.concat(chunks);
            validateResponse(canonical(utf8(bytes)));
            res.setHeader("connection", "close");
            res.setHeader("cache-control", "no-store");
            res.removeHeader("etag");
            responseValid = true;
            const cb =
              typeof chunk === "function"
                ? chunk
                : typeof encoding === "function"
                ? encoding
                : callback;
            return originalEnd(bytes, cb);
          } catch {
            close();
            return res;
          }
        }) as typeof res.end;
        res.writeHead = ((...args: any[]) => {
          if (!responseValid || denied) {
            close();
            return res;
          }
          return (originalWriteHead as any)(...args);
        }) as typeof res.writeHead;
        // Streaming headers/trailers and redirects are not bootstrap responses.
        res.flushHeaders = () => {
          close();
        };
        res.addTrailers = () => {
          close();
        };
        req.once("aborted", close);
        res.once("finish", () => {
          clearTimeout(timer);
          active.delete(res);
          if (!responseValid || denied) return close();
          completed++;
          busy = false;
          if (completed === 19) clearTimeout(lifetime);
        });
        res.once("close", () => {
          clearTimeout(timer);
          active.delete(res);
          if (!res.writableFinished) close();
        });
        next();
      } catch {
        close();
        res.destroy();
      }
    });
  });
  // body-parser marks its own consumed-body state; the real app's existing
  // JSON/urlencoded parsers must skip this already parsed body. Tested with
  // actual installed Express, not a fabricated/replayed IncomingMessage.
  router.use(
    express.raw({ limit: 8192, type: "application/json", inflate: false })
  );
  router.use((req: Request, res: Response, next) => {
    try {
      if (!usable()) throw fail();
      const body = expected().body;
      if (body) {
        if (
          !Buffer.isBuffer(req.body) ||
          !req.body.equals(Buffer.from(JSON.stringify(body)))
        )
          throw fail();
        req.body = canonical(req.body.toString("utf8"));
      } else if (Buffer.isBuffer(req.body) && req.body.length) throw fail();
      next();
    } catch {
      close();
      res.destroy();
    }
  });
  router.use(
    (_error: unknown, _req: Request, res: Response, _next: unknown) => {
      close();
      res.destroy();
    }
  );
  return Object.freeze({
    middleware: router as RequestHandler,
    close,
    summary: () =>
      Object.freeze({
        classification: "APPLICATION_ADMISSION_ONLY",
        completedRequests: completed,
        denied,
        complete: completed === 19,
        resourceOwnership: "NOT_ESTABLISHED",
        applicationDrain: "NOT_VERIFIED",
        activationGranted: false,
      }),
  });
}
