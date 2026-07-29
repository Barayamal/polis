/**
 * Private FNCP provider-side XID allowlist adapter.
 *
 * Modified by Barayamal on 29 July 2026.
 *
 * This adapter is intentionally separate from the public/moderator
 * xidAllowList API. It exposes only three naturally idempotent, exact-scope
 * operations to the Community Pulse access authority:
 *
 *   POST /fncp/private/xid-allowlist/upsert
 *   POST /fncp/private/xid-allowlist/readback
 *   POST /fncp/private/xid-allowlist/remove
 *
 * The route must also be kept behind a network-private origin. The bearer
 * credential is defence in depth, not a substitute for that network boundary.
 */

import crypto from "node:crypto";
import type { RequestHandler, Response } from "express";

import pg from "../db/pg-query";

export const FNCP_PROVIDER_ALLOWLIST_PATHS = {
  upsert: "/fncp/private/xid-allowlist/upsert",
  readback: "/fncp/private/xid-allowlist/readback",
  remove: "/fncp/private/xid-allowlist/remove",
} as const;

type ProviderAllowlistOperation = keyof typeof FNCP_PROVIDER_ALLOWLIST_PATHS;

const CONVERSATION_ID = /^[0-9][0-9A-Za-z]{1,99}$/u;
const PARTICIPANT_XID = /^fncp_[A-Za-z0-9_-]{16,251}$/u;
const CREDENTIAL = /^[A-Za-z0-9_-]{32,512}$/u;
const IDEMPOTENCY_KEY = /^(allow|remove)-[A-Za-z0-9_-]{32,512}$/u;

interface FncpProviderAllowlistConfig {
  enabled: boolean;
  conversationId: string;
  bearerCredential: string;
}

interface ProviderAllowlistRequestShape {
  headers: Record<string, unknown>;
  query?: Record<string, unknown>;
  body?: unknown;
}

interface ProviderAllowlistAuthorized {
  authorized: true;
  conversationId: string;
  participantXid: string;
  operationVersion: 1 | 2 | null;
}

interface ProviderAllowlistDenied {
  authorized: false;
  status: 400 | 404;
}

export type ProviderAllowlistDecision =
  | ProviderAllowlistAuthorized
  | ProviderAllowlistDenied;

export interface ProviderAllowlistState {
  conversationReady: boolean;
  operationAccepted: boolean;
  operationVersion: number | null;
  present: boolean;
}

export interface FncpProviderAllowlistStore {
  upsert(
    conversationId: string,
    participantXid: string,
    operationVersion: 1
  ): Promise<ProviderAllowlistState>;
  readback(
    conversationId: string,
    participantXid: string
  ): Promise<ProviderAllowlistState>;
  remove(
    conversationId: string,
    participantXid: string,
    operationVersion: 2
  ): Promise<ProviderAllowlistState>;
}

interface ProviderAllowlistHandlerDependencies {
  store: FncpProviderAllowlistStore;
  loadConfig: () => FncpProviderAllowlistConfig;
}

function singleHeader(headers: Record<string, unknown>, name: string): string {
  const value = headers[name.toLowerCase()];
  return typeof value === "string" ? value : "";
}

function sameCredential(supplied: string, expected: string): boolean {
  if (!supplied || !expected) {
    return false;
  }
  const left = crypto.createHash("sha256").update(supplied).digest();
  const right = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(left, right);
}

function exactRequestBody(
  value: unknown,
  operation: ProviderAllowlistOperation
):
  | {
      conversationId: string;
      participantXid: string;
      operationVersion: 1 | 2 | null;
    }
  | undefined {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    return undefined;
  }
  const body = value as Record<string, unknown>;
  const expectedKeys =
    operation === "readback"
      ? "conversationId,participantXid"
      : "conversationId,operationVersion,participantXid";
  if (
    Object.keys(body).sort().join(",") !== expectedKeys ||
    typeof body.conversationId !== "string" ||
    typeof body.participantXid !== "string"
  ) {
    return undefined;
  }
  return {
    conversationId: body.conversationId,
    participantXid: body.participantXid,
    operationVersion:
      operation === "upsert"
        ? body.operationVersion === 1
          ? 1
          : null
        : operation === "remove"
        ? body.operationVersion === 2
          ? 2
          : null
        : null,
  };
}

function expectedIdempotencyPrefix(
  operation: ProviderAllowlistOperation
): "allow" | "remove" | undefined {
  if (operation === "upsert") return "allow";
  if (operation === "remove") return "remove";
  return undefined;
}

export function loadFncpProviderAllowlistConfig(
  // Read at request time so an emergency disable takes effect immediately.
  // eslint-disable-next-line no-restricted-properties
  env: NodeJS.ProcessEnv = process.env
): FncpProviderAllowlistConfig {
  return {
    enabled: env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT === "true",
    conversationId: env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID || "",
    bearerCredential: env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL || "",
  };
}

/**
 * Authenticate and validate one authority request without returning credentials
 * or idempotency material to the handler. Authentication failures deliberately
 * collapse to 404 so the private capability is not discoverable from the
 * application origin.
 */
export function evaluateFncpProviderAllowlistRequest(
  request: ProviderAllowlistRequestShape,
  operation: ProviderAllowlistOperation,
  config: FncpProviderAllowlistConfig
): ProviderAllowlistDecision {
  const authorization = singleHeader(request.headers, "authorization");
  const bearerMatch = /^Bearer ([A-Za-z0-9_-]{32,512})$/u.exec(authorization);

  if (
    !config.enabled ||
    !CONVERSATION_ID.test(config.conversationId) ||
    !CREDENTIAL.test(config.bearerCredential) ||
    !bearerMatch ||
    !sameCredential(bearerMatch[1], config.bearerCredential)
  ) {
    return { authorized: false, status: 404 };
  }

  if (
    singleHeader(request.headers, "cookie") ||
    singleHeader(request.headers, "origin") ||
    (request.query && Object.keys(request.query).length > 0)
  ) {
    return { authorized: false, status: 404 };
  }

  const mediaType = singleHeader(request.headers, "content-type")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") {
    return { authorized: false, status: 400 };
  }

  const body = exactRequestBody(request.body, operation);
  if (
    !body ||
    (operation !== "readback" && body.operationVersion === null) ||
    body.conversationId !== config.conversationId ||
    !PARTICIPANT_XID.test(body.participantXid)
  ) {
    return { authorized: false, status: 400 };
  }

  const expectedPrefix = expectedIdempotencyPrefix(operation);
  const idempotencyKey = singleHeader(request.headers, "idempotency-key");
  if (expectedPrefix) {
    if (
      !IDEMPOTENCY_KEY.test(idempotencyKey) ||
      !idempotencyKey.startsWith(`${expectedPrefix}-`)
    ) {
      return { authorized: false, status: 400 };
    }
  } else if (idempotencyKey) {
    return { authorized: false, status: 400 };
  }

  return {
    authorized: true,
    conversationId: body.conversationId,
    participantXid: body.participantXid,
    operationVersion: body.operationVersion,
  };
}

export const postgresProviderAllowlistStore: FncpProviderAllowlistStore = {
  async upsert(conversationId, participantXid, operationVersion) {
    const rows = await pg.queryP<{
      conversation_ready: boolean;
      operation_accepted: boolean;
      operation_version: number | null;
      present: boolean;
    }>(
      `WITH target AS (
         SELECT c.zid, c.owner
         FROM zinvites z
         INNER JOIN conversations c ON c.zid = z.zid
         WHERE z.zinvite = $1
           AND c.use_xid_whitelist IS TRUE
       ),
       operation AS (
         INSERT INTO fncp_provider_allowlist_operations (
           zid, xid, operation_version, desired_present
         )
         SELECT target.zid, $2, $3, TRUE
         FROM target
         ON CONFLICT (zid, xid) DO UPDATE
           SET operation_version = EXCLUDED.operation_version,
               desired_present = EXCLUDED.desired_present
           WHERE
             fncp_provider_allowlist_operations.operation_version <
               EXCLUDED.operation_version
             OR (
               fncp_provider_allowlist_operations.operation_version =
                 EXCLUDED.operation_version
               AND fncp_provider_allowlist_operations.desired_present =
                 EXCLUDED.desired_present
             )
         RETURNING zid, operation_version
       ),
       allowed AS (
         INSERT INTO xid_whitelist (xid, zid, owner)
         SELECT $2, target.zid, target.owner
         FROM target
         INNER JOIN operation ON operation.zid = target.zid
         ON CONFLICT (owner, xid) DO UPDATE
           SET zid = EXCLUDED.zid
           WHERE xid_whitelist.zid = EXCLUDED.zid
         RETURNING zid, xid
       )
       SELECT
         EXISTS (SELECT 1 FROM target) AS conversation_ready,
         EXISTS (SELECT 1 FROM operation) AS operation_accepted,
         COALESCE(
           (SELECT operation_version FROM operation),
           (
             SELECT current.operation_version
             FROM fncp_provider_allowlist_operations current
             INNER JOIN target ON target.zid = current.zid
             WHERE current.xid = $2
           )
         ) AS operation_version,
         EXISTS (SELECT 1 FROM allowed) AS present;`,
      [conversationId, participantXid, operationVersion]
    );
    return {
      conversationReady: rows[0]?.conversation_ready === true,
      operationAccepted: rows[0]?.operation_accepted === true,
      operationVersion: rows[0]?.operation_version ?? null,
      present: rows[0]?.present === true,
    };
  },

  async readback(conversationId, participantXid) {
    // Use the primary pool so an issuance readback cannot be satisfied by a
    // lagging replica after an upsert or removal.
    const rows = await pg.queryP<{
      conversation_ready: boolean;
      operation_version: number | null;
      present: boolean;
    }>(
      `WITH target AS (
         SELECT c.zid, c.owner
         FROM zinvites z
         INNER JOIN conversations c ON c.zid = z.zid
         WHERE z.zinvite = $1
           AND c.use_xid_whitelist IS TRUE
       )
       SELECT
         EXISTS (SELECT 1 FROM target) AS conversation_ready,
         (
           SELECT current.operation_version
           FROM fncp_provider_allowlist_operations current
           INNER JOIN target ON target.zid = current.zid
           WHERE current.xid = $2
         ) AS operation_version,
         EXISTS (
           SELECT 1
           FROM xid_whitelist allowed
           INNER JOIN target
             ON target.zid = allowed.zid
            AND target.owner = allowed.owner
           WHERE allowed.xid = $2
         ) AS present;`,
      [conversationId, participantXid]
    );
    return {
      conversationReady: rows[0]?.conversation_ready === true,
      operationAccepted: true,
      operationVersion: rows[0]?.operation_version ?? null,
      present: rows[0]?.present === true,
    };
  },

  async remove(conversationId, participantXid, operationVersion) {
    const rows = await pg.queryP<{
      conversation_ready: boolean;
      operation_accepted: boolean;
      operation_version: number | null;
      present: boolean;
    }>(
      `WITH target AS (
         SELECT c.zid, c.owner
         FROM zinvites z
         INNER JOIN conversations c ON c.zid = z.zid
         WHERE z.zinvite = $1
           AND c.use_xid_whitelist IS TRUE
       ),
       operation AS (
         INSERT INTO fncp_provider_allowlist_operations (
           zid, xid, operation_version, desired_present
         )
         SELECT target.zid, $2, $3, FALSE
         FROM target
         ON CONFLICT (zid, xid) DO UPDATE
           SET operation_version = EXCLUDED.operation_version,
               desired_present = EXCLUDED.desired_present
           WHERE
             fncp_provider_allowlist_operations.operation_version <
               EXCLUDED.operation_version
             OR (
               fncp_provider_allowlist_operations.operation_version =
                 EXCLUDED.operation_version
               AND fncp_provider_allowlist_operations.desired_present =
                 EXCLUDED.desired_present
             )
         RETURNING zid, operation_version
       ),
       removed AS (
         DELETE FROM xid_whitelist allowed
         USING target, operation
         WHERE allowed.zid = target.zid
           AND operation.zid = target.zid
           AND allowed.owner = target.owner
           AND allowed.xid = $2
         RETURNING allowed.xid
       )
       SELECT
         EXISTS (SELECT 1 FROM target) AS conversation_ready,
         EXISTS (SELECT 1 FROM operation) AS operation_accepted,
         COALESCE(
           (SELECT operation_version FROM operation),
           (
             SELECT current.operation_version
             FROM fncp_provider_allowlist_operations current
             INNER JOIN target ON target.zid = current.zid
             WHERE current.xid = $2
           )
         ) AS operation_version,
         CASE
           WHEN EXISTS (SELECT 1 FROM operation) THEN FALSE
           ELSE EXISTS (
             SELECT 1
             FROM xid_whitelist allowed
             INNER JOIN target
               ON target.zid = allowed.zid
              AND target.owner = allowed.owner
             WHERE allowed.xid = $2
           )
         END AS present;`,
      [conversationId, participantXid, operationVersion]
    );
    return {
      conversationReady: rows[0]?.conversation_ready === true,
      operationAccepted: rows[0]?.operation_accepted === true,
      operationVersion: rows[0]?.operation_version ?? null,
      present: rows[0]?.present === true,
    };
  },
};

function privateHeaders(res: Response): Response {
  return res.set({
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    Vary: "Authorization",
    "X-Content-Type-Options": "nosniff",
  });
}

function privateError(res: Response, status: number): void {
  const error =
    status === 404
      ? "Not found."
      : status === 503
      ? "Provider unavailable."
      : "Invalid request.";
  privateHeaders(res).status(status).json({ error });
}

function createHandler(
  operation: ProviderAllowlistOperation,
  dependencies: ProviderAllowlistHandlerDependencies
): RequestHandler {
  return async function fncpProviderAllowlistHandler(req, res) {
    const decision = evaluateFncpProviderAllowlistRequest(
      {
        headers: req.headers as Record<string, unknown>,
        query: req.query as Record<string, unknown>,
        body: req.body,
      },
      operation,
      dependencies.loadConfig()
    );

    if (decision.authorized === false) {
      privateError(res, decision.status);
      return;
    }

    try {
      if (operation === "readback") {
        const state = await dependencies.store.readback(
          decision.conversationId,
          decision.participantXid
        );
        if (!state.conversationReady) {
          privateError(res, 503);
          return;
        }
        privateHeaders(res).status(200).json({
          conversationId: decision.conversationId,
          participantXid: decision.participantXid,
          operationVersion: state.operationVersion,
          present: state.present,
        });
        return;
      }

      if (operation === "upsert") {
        const state = await dependencies.store.upsert(
          decision.conversationId,
          decision.participantXid,
          1
        );
        if (
          !state.conversationReady ||
          !state.operationAccepted ||
          state.operationVersion !== 1 ||
          !state.present
        ) {
          privateError(res, 503);
          return;
        }
      } else {
        const state = await dependencies.store.remove(
          decision.conversationId,
          decision.participantXid,
          2
        );
        if (
          !state.conversationReady ||
          !state.operationAccepted ||
          state.operationVersion !== 2 ||
          state.present
        ) {
          privateError(res, 503);
          return;
        }
      }

      privateHeaders(res).status(204).end();
    } catch {
      // Never serialize database, scope, credential or XID details.
      privateError(res, 503);
    }
  };
}

export function createFncpProviderAllowlistHandlers(
  dependencies: Partial<ProviderAllowlistHandlerDependencies> = {}
): Record<ProviderAllowlistOperation, RequestHandler> {
  const resolved: ProviderAllowlistHandlerDependencies = {
    store: dependencies.store ?? postgresProviderAllowlistStore,
    loadConfig: dependencies.loadConfig ?? loadFncpProviderAllowlistConfig,
  };
  return {
    upsert: createHandler("upsert", resolved),
    readback: createHandler("readback", resolved),
    remove: createHandler("remove", resolved),
  };
}

export const fncpProviderAllowlistHandlers =
  createFncpProviderAllowlistHandlers();
