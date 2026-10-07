import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test } from "@jest/globals";

const commentsSource = readFileSync(
  resolve(__dirname, "../../src/routes/comments.ts"),
  "utf8"
);

describe("FNCP comment egress source contract", () => {
  test("all optional comment processors are controlled by one request policy", () => {
    expect(commentsSource).toContain(
      "const processingPolicy = fncpParticipantProcessingPolicy(req);"
    );
    expect(commentsSource).toMatch(
      /processingPolicy\.allowExternalModeration\s*&&\s*\(await isProConvo/
    );
    expect(commentsSource).toMatch(
      /processingPolicy\.allowExternalLanguageDetection\s*\?\s*await detectLanguage\(txt\)\s*:\s*\[\{ confidence: null, language: null \}\]/
    );
    expect(commentsSource).toContain(
      "if (!processingPolicy.allowOutboundNotifications)"
    );
  });

  test("the FNCP notification stop precedes every statement email call", () => {
    const handlerStart = commentsSource.indexOf(
      "async function handle_POST_comments("
    );
    const bulkHandlerStart = commentsSource.indexOf(
      "async function handle_POST_comments_bulk("
    );
    const participantHandler = commentsSource.slice(
      handlerStart,
      bulkHandlerStart
    );
    const stop = participantHandler.indexOf(
      "if (!processingPolicy.allowOutboundNotifications)"
    );
    const email = participantHandler.indexOf("sendCommentModerationEmail(");

    expect(handlerStart).toBeGreaterThanOrEqual(0);
    expect(bulkHandlerStart).toBeGreaterThan(handlerStart);
    expect(stop).toBeGreaterThanOrEqual(0);
    expect(email).toBeGreaterThan(stop);
  });
});
