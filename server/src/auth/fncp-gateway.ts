/**
 * First Nations Community Pulse private-origin gateway enforcement.
 *
 * Modified by Barayamal on 26–27 July 2026.
 *
 * This optional middleware is deliberately scoped to the configured FNCP
 * conversation and the participant API routes used by the Barayamal gateway.
 * It is not a replacement for network-private origin controls or the XID
 * allowlist revalidation in ensure-participant.ts.
 */

import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import {
  isFncpLogBoundaryActive,
  markFncpSensitiveRequest,
  runInFncpLogBoundary,
} from "./fncp-log-boundary";

const PARTICIPANT_ROUTE_DEFINITIONS = [
  "GET /api/v3/comments",
  "GET /api/v3/math/pca2",
  "GET /api/v3/nextComment",
  "GET /api/v3/participationInit",
  "POST /api/v3/comments",
  "POST /api/v3/votes",
] as const;

function normalizePath(path: string): string {
  const withoutTrailingSlash =
    path.length > 1 ? path.replace(/\/+$/u, "") : path;
  return withoutTrailingSlash.toLowerCase();
}

const PARTICIPANT_ROUTES: ReadonlyMap<string, string> = new Map(
  PARTICIPANT_ROUTE_DEFINITIONS.map((route) => {
    const separator = route.indexOf(" ");
    const method = route.slice(0, separator);
    const path = route.slice(separator + 1);
    return [`${method} ${normalizePath(path)}`, path] as const;
  })
);

const HEAD_ALIAS_PARTICIPANT_PATHS = new Set(
  PARTICIPANT_ROUTE_DEFINITIONS.filter((route) => route.startsWith("GET ")).map(
    (route) => normalizePath(route.slice(route.indexOf(" ") + 1))
  )
);

// The dedicated Option C participant capability manifest contains only the
// six routes above. joinWithInvite runs hybridAuthOptional and may create an
// OIDC/anonymous user before its route handler executes, so an FNCP instance
// must reject it in this earlier middleware regardless of supplied identity,
// invitation, or provider allowlist state.
const FNCP_DISABLED_ROUTE_KEYS = new Set(["POST /api/v3/joinwithinvite"]);

const IDENTITY_KEYS = new Set([
  "access_token",
  "authorization",
  "email",
  "id_token",
  "jwt",
  "name",
  "password",
  "pid",
  "refresh_token",
  "session",
  "token",
  "uid",
  "x_name",
  "x_profile_image_url",
  "xid",
]);

const CONVERSATION_ID = /^[0-9][A-Za-z0-9_-]{5,99}$/;
const XID = /^[A-Za-z0-9_-]{16,256}$/;

export interface FncpGatewayConfig {
  enabled: boolean;
  activationValid: boolean;
  conversationId: string;
  sharedSecret: string;
}

interface GatewayRequestShape {
  method: string;
  path: string;
  headers: Record<string, unknown>;
  query?: Record<string, unknown>;
  body?: Record<string, unknown>;
}

export interface FncpGatewayDecision {
  enforce: boolean;
  status?: number;
  error?: string;
  conversationId?: string;
  participantXid?: string;
}

function headerValue(headers: Record<string, unknown>, name: string): string {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) {
    return value.length === 1 && typeof value[0] === "string" ? value[0] : "";
  }
  return typeof value === "string" ? value : "";
}

function scalarString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function suppliedConversations(request: GatewayRequestShape): string[] {
  return [
    scalarString(request.query?.conversation_id),
    scalarString(request.query?.conversationId),
    scalarString(request.body?.conversation_id),
    scalarString(request.body?.conversationId),
  ].filter(Boolean);
}

function hasIdentityInput(value: unknown, depth = 0): boolean {
  if (depth > 6 || value === null || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => hasIdentityInput(item, depth + 1));
  }
  return Object.entries(value as Record<string, unknown>).some(
    ([key, item]) =>
      IDENTITY_KEYS.has(key.toLowerCase()) || hasIdentityInput(item, depth + 1)
  );
}

function sameSecret(supplied: string, expected: string): boolean {
  if (!supplied || !expected) {
    return false;
  }
  const left = crypto.createHash("sha256").update(supplied).digest();
  const right = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(left, right);
}

export function loadFncpGatewayConfig(
  // Read at request time so a dedicated release remains fail-closed if its
  // configuration changes unexpectedly. Do not disable this switch as an
  // emergency action: deny ingress and revoke invitations instead.
  // eslint-disable-next-line no-restricted-properties
  env: NodeJS.ProcessEnv = process.env
): FncpGatewayConfig {
  const activation = env.FNCP_GATEWAY_ENFORCEMENT;
  const dedicatedReleaseConfigured =
    env.FNCP_OPTION_C_RELEASE_MODE !== undefined;
  const dedicatedProduction = env.FNCP_OPTION_C_RELEASE_MODE === "production";
  return {
    enabled: dedicatedReleaseConfigured || activation === "true",
    activationValid:
      (activation === undefined ||
        activation === "false" ||
        activation === "true") &&
      (!dedicatedReleaseConfigured ||
        (dedicatedProduction && activation === "true")),
    conversationId: env.FNCP_GATEWAY_CONVERSATION_ID || "",
    sharedSecret: env.FNCP_GATEWAY_SHARED_SECRET || "",
  };
}

export function evaluateFncpGatewayRequest(
  request: GatewayRequestShape,
  config: FncpGatewayConfig
): FncpGatewayDecision {
  if (!config.enabled) {
    return { enforce: false };
  }
  if (
    !config.activationValid ||
    !CONVERSATION_ID.test(config.conversationId) ||
    config.sharedSecret.length < 32
  ) {
    return {
      enforce: true,
      status: 503,
      error: "FNCP gateway is not configured.",
    };
  }

  const requestMethod = request.method.toUpperCase();
  const requestPath = normalizePath(request.path);
  const routeKey = `${requestMethod} ${requestPath}`;

  if (FNCP_DISABLED_ROUTE_KEYS.has(routeKey)) {
    return { enforce: true, status: 404, error: "Not found." };
  }

  const canonicalPath = PARTICIPANT_ROUTES.get(routeKey);
  const routeIsParticipant = canonicalPath !== undefined;
  const pathIsCanonical = request.path === canonicalPath;
  const isHeadAlias =
    requestMethod === "HEAD" && HEAD_ALIAS_PARTICIPANT_PATHS.has(requestPath);
  const requestedConversations = suppliedConversations(request);
  const claimedConversation = headerValue(
    request.headers,
    "x-fncp-conversation-id"
  );
  const claimsGatewayAccess =
    !!claimedConversation ||
    !!headerValue(request.headers, "x-fncp-gateway-key") ||
    !!headerValue(request.headers, "x-fncp-participant-xid");

  const targetsConfiguredConversation =
    requestedConversations.includes(config.conversationId) ||
    claimedConversation === config.conversationId;
  const hasConflictingConversation = requestedConversations.some(
    (conversation) => conversation !== config.conversationId
  );

  if (!routeIsParticipant) {
    // Express aliases HEAD to GET automatically. Deny that alias for protected
    // GET routes, while preserving legitimate admin methods that share a path
    // with participant reads (for example PUT /api/v3/conversations).
    if (isHeadAlias && targetsConfiguredConversation) {
      return { enforce: true, status: 404, error: "Not found." };
    }
    if (claimsGatewayAccess) {
      return { enforce: true, status: 404, error: "Not found." };
    }
    return { enforce: false };
  }

  if (
    !pathIsCanonical &&
    (targetsConfiguredConversation || claimsGatewayAccess)
  ) {
    return { enforce: true, status: 404, error: "Not found." };
  }

  if (!targetsConfiguredConversation && !claimsGatewayAccess) {
    return { enforce: false };
  }

  if (claimedConversation && claimedConversation !== config.conversationId) {
    return { enforce: true, status: 403, error: "Wrong conversation." };
  }
  if (hasConflictingConversation) {
    return { enforce: true, status: 403, error: "Wrong conversation." };
  }
  if (
    !sameSecret(
      headerValue(request.headers, "x-fncp-gateway-key"),
      config.sharedSecret
    )
  ) {
    return { enforce: true, status: 403, error: "Gateway access required." };
  }
  if (claimedConversation !== config.conversationId) {
    return { enforce: true, status: 403, error: "Gateway access required." };
  }

  const participantXid = headerValue(request.headers, "x-fncp-participant-xid");
  if (!XID.test(participantXid)) {
    return { enforce: true, status: 403, error: "Gateway access required." };
  }

  if (
    headerValue(request.headers, "authorization") ||
    headerValue(request.headers, "cookie") ||
    hasIdentityInput(request.query) ||
    hasIdentityInput(request.body)
  ) {
    return {
      enforce: true,
      status: 400,
      error: "Conflicting participant identity.",
    };
  }

  return {
    enforce: true,
    conversationId: config.conversationId,
    participantXid,
  };
}

export function fncpGatewayMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const decision = evaluateFncpGatewayRequest(
    {
      method: req.method,
      path: req.path,
      headers: req.headers as Record<string, unknown>,
      query: req.query as Record<string, unknown>,
      body:
        req.body && typeof req.body === "object"
          ? (req.body as Record<string, unknown>)
          : undefined,
    },
    loadFncpGatewayConfig()
  );

  if (!decision.enforce) {
    next();
    return;
  }

  markFncpSensitiveRequest(req);
  const continueInsideBoundary = () => {
    if (decision.status) {
      res
        .status(decision.status)
        .set("Cache-Control", "no-store")
        .json({ error: decision.error });
      return;
    }

    // Gateway requests are authenticated by the private origin on every call.
    // Pol.is may still issue its normal participant JWT internally, but that
    // bearer token must never cross the FNCP gateway boundary. Install this
    // response filter only after the exact gateway assertion has passed so
    // ordinary Pol.is/OIDC responses remain byte-for-byte unchanged.
    const originalJson = res.json.bind(res);
    res.json = function fncpGatewayJson(body: unknown) {
      if (
        body &&
        typeof body === "object" &&
        !Array.isArray(body) &&
        Object.prototype.hasOwnProperty.call(body, "auth")
      ) {
        const safeBody = { ...(body as Record<string, unknown>) };
        delete safeBody.auth;
        return originalJson(safeBody);
      }
      return originalJson(body);
    };

    const query = req.query as Record<string, unknown>;
    query.conversation_id = decision.conversationId;
    query.xid = decision.participantXid;

    if (req.body && typeof req.body === "object") {
      const body = req.body as Record<string, unknown>;
      delete body.conversationId;
      body.conversation_id = decision.conversationId;
      body.xid = decision.participantXid;
    }

    next();
  };

  if (isFncpLogBoundaryActive()) {
    continueInsideBoundary();
  } else {
    runInFncpLogBoundary(continueInsideBoundary);
  }
}
