import { describe, expect, test } from "@jest/globals";

import { fncpParticipantProcessingPolicy } from "../../src/auth/fncp-participant-policy";

const configured = {
  FNCP_GATEWAY_CONVERSATION_ID: "8fncpRound",
} as NodeJS.ProcessEnv;

describe("FNCP participant-processing policy", () => {
  test.each([
    {
      name: "trusted gateway header",
      request: {
        headers: { "x-fncp-conversation-id": "8fncpRound" },
      },
    },
    {
      name: "parsed request body",
      request: {
        body: { conversation_id: "8fncpRound" },
      },
    },
    {
      name: "parsed query",
      request: {
        query: { conversation_id: "8fncpRound" },
      },
    },
  ])("disables every optional external processor for $name", ({ request }) => {
    expect(fncpParticipantProcessingPolicy(request, configured)).toEqual({
      isFncpConversation: true,
      allowExternalLanguageDetection: false,
      allowExternalModeration: false,
      allowOutboundNotifications: false,
    });
  });

  test("does not change processing policy for another Pol.is conversation", () => {
    expect(
      fncpParticipantProcessingPolicy(
        {
          headers: { "X-FNCP-Conversation-ID": "9anotherRound" },
          body: { conversation_id: "9anotherRound" },
        },
        configured
      )
    ).toEqual({
      isFncpConversation: false,
      allowExternalLanguageDetection: true,
      allowExternalModeration: true,
      allowOutboundNotifications: true,
    });
  });

  test("does not silently classify traffic when the FNCP conversation is unset", () => {
    expect(
      fncpParticipantProcessingPolicy(
        { body: { conversation_id: "8fncpRound" } },
        {} as NodeJS.ProcessEnv
      )
    ).toEqual({
      isFncpConversation: false,
      allowExternalLanguageDetection: true,
      allowExternalModeration: true,
      allowOutboundNotifications: true,
    });
  });
});
