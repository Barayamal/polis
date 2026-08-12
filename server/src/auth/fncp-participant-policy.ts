/**
 * First Nations Community Pulse participant-processing policy.
 *
 * The Community Pulse privacy boundary keeps participant statements inside the
 * reviewed Pol.is deployment. Optional Pol.is enrichment and notification
 * processors must therefore remain disabled for the configured FNCP
 * conversation, even if those processors are enabled for another conversation
 * hosted by the same server.
 */

interface FncpParticipantRequest {
  body?: Record<string, unknown>;
  query?: Record<string, unknown>;
  headers?: Record<string, unknown>;
}

export interface FncpParticipantProcessingPolicy {
  isFncpConversation: boolean;
  allowExternalLanguageDetection: boolean;
  allowExternalModeration: boolean;
  allowOutboundNotifications: boolean;
}

function scalar(value: unknown): string {
  if (Array.isArray(value)) {
    return value.length === 1 && typeof value[0] === "string" ? value[0] : "";
  }
  return typeof value === "string" ? value : "";
}

function header(
  headers: Record<string, unknown> | undefined,
  name: string
): string {
  if (!headers) {
    return "";
  }
  const direct = headers[name];
  if (direct !== undefined) {
    return scalar(direct);
  }
  const found = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === name.toLowerCase()
  );
  return found ? scalar(found[1]) : "";
}

export function fncpParticipantProcessingPolicy(
  request: FncpParticipantRequest,
  // Read at request time so an emergency conversation change does not require
  // a process restart. A missing configuration does not change other Pol.is
  // conversations; the FNCP gateway itself remains responsible for failing
  // closed when its required configuration is absent.
  // eslint-disable-next-line no-restricted-properties
  env: NodeJS.ProcessEnv = process.env
): FncpParticipantProcessingPolicy {
  const configuredConversation = env.FNCP_GATEWAY_CONVERSATION_ID || "";
  const suppliedConversations = [
    header(request.headers, "x-fncp-conversation-id"),
    scalar(request.body?.conversation_id),
    scalar(request.query?.conversation_id),
  ].filter(Boolean);

  const isFncpConversation =
    configuredConversation.length > 0 &&
    suppliedConversations.includes(configuredConversation);

  return {
    isFncpConversation,
    allowExternalLanguageDetection: !isFncpConversation,
    allowExternalModeration: !isFncpConversation,
    allowOutboundNotifications: !isFncpConversation,
  };
}
