/**
 * Request-scoped logging boundary for the private First Nations Community
 * Pulse (FNCP) participant and authority paths.
 *
 * FNCP requests carry an opaque XID and private gateway credentials. Once a
 * request enters this boundary, application logs are deliberately reduced to
 * a generic event before they reach any Winston transport. This is a defence
 * in depth backstop for older Pol.is code which logs participant identifiers
 * from local variables rather than from the Express request object.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import type { NextFunction, Request, Response } from "express";

const FNCP_PARTICIPANT_PATHS = new Set([
  "/api/v3/comments",
  "/api/v3/math/pca2",
  "/api/v3/nextcomment",
  "/api/v3/participationinit",
  "/api/v3/votes",
]);

const FNCP_PRIVATE_PATH_PREFIX = "/fncp/private/";
const FNCP_HEADER_PREFIX = "x-fncp-";
const fncpRequests = new WeakSet<object>();
const fncpLogScope = new AsyncLocalStorage<boolean>();

type RequestShape = Pick<Request, "headers" | "method" | "path" | "query">;
type LogInfo = Record<PropertyKey, unknown> & {
  level: string;
  message: unknown;
};

function normalizePath(path: string): string {
  return (path.length > 1 ? path.replace(/\/+$/u, "") : path).toLowerCase();
}

function scalar(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function hasFncpHeader(headers: Request["headers"]): boolean {
  return Object.keys(headers).some((name) =>
    name.toLowerCase().startsWith(FNCP_HEADER_PREFIX)
  );
}

/**
 * Mark sensitive requests before request formatters and JSON parsers run.
 *
 * Successful gateway calls always carry x-fncp-* headers. Direct GET attempts
 * are also identified by the configured conversation query. Protected POST
 * paths are conservatively bounded while enforcement is active because their
 * conversation and identity are carried in the not-yet-parsed body.
 */
export function shouldEnterFncpLogBoundary(
  request: RequestShape,
  // Read at request time so an emergency enable/disable takes effect without a
  // process restart.
  // eslint-disable-next-line no-restricted-properties
  env: NodeJS.ProcessEnv = process.env
): boolean {
  const path = normalizePath(request.path);
  if (
    path.startsWith(FNCP_PRIVATE_PATH_PREFIX) ||
    hasFncpHeader(request.headers)
  ) {
    return true;
  }

  if (env.FNCP_GATEWAY_ENFORCEMENT !== "true") {
    return false;
  }

  const isParticipantPath = FNCP_PARTICIPANT_PATHS.has(path);
  if (!isParticipantPath) {
    return false;
  }

  const configuredConversation = env.FNCP_GATEWAY_CONVERSATION_ID || "";
  const queryConversation =
    scalar(request.query?.conversation_id) ||
    scalar(request.query?.conversationId);

  if (configuredConversation && queryConversation === configuredConversation) {
    return true;
  }

  // POST comments/votes can carry the configured conversation, XID, session,
  // or invitation token exclusively in a JSON body which has not been parsed
  // yet. Suppress those request logs rather than risk body-parser error text
  // or a development URL formatter retaining participant material.
  return request.method.toUpperCase() === "POST";
}

export function markFncpSensitiveRequest(request: object): void {
  fncpRequests.add(request);
}

export function isFncpSensitiveRequest(request: unknown): boolean {
  return (
    typeof request === "object" && request !== null && fncpRequests.has(request)
  );
}

export function isFncpLogBoundaryActive(): boolean {
  return fncpLogScope.getStore() === true;
}

export function runInFncpLogBoundary<T>(callback: () => T): T {
  return fncpLogScope.run(true, callback);
}

export function fncpLogBoundaryMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction
): void {
  if (!shouldEnterFncpLogBoundary(req)) {
    next();
    return;
  }

  markFncpSensitiveRequest(req);
  runInFncpLogBoundary(next);
}

/**
 * Winston formatter helper. In an FNCP request scope, discard the entire
 * application-provided message, splat arguments and metadata object. Retain
 * only the log level and a fixed event name. This is structural omission, not
 * best-effort matching of secret values.
 */
export function minimizeFncpLogInfo(info: LogInfo): LogInfo {
  if (!isFncpLogBoundaryActive()) {
    return info;
  }

  const levelSymbol = Symbol.for("level");
  const originalLevel =
    typeof info.level === "string"
      ? info.level
      : typeof info[levelSymbol] === "string"
      ? info[levelSymbol]
      : "info";

  for (const key of Reflect.ownKeys(info)) {
    delete info[key];
  }

  info.level = originalLevel;
  info[levelSymbol] = originalLevel;
  info.message = "fncp_request_event";
  info.service = "server";
  return info;
}
