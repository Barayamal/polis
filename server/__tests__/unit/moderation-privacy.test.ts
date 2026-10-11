/** Actual moderation/route modules; every external, identity and DB boundary
 * is doubled. All addresses, identifiers, content and results are invented. */
import { afterEach, beforeEach, expect, jest, test } from "@jest/globals";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const COMMENT = "INVENTED_PRIVATE_COMMENT_SENTINEL";
const TOPIC = "INVENTED_TOPIC_SENTINEL";
const MODEL_TRACE = "INVENTED_PRIVATE_MODEL_TRACE";
const OWNER_EMAIL = "invented-owner@example.invalid";
const OWNER_SUBJECT = "invented-oidc-subject";
const CONVERSATION = "8Synthetic";
const FORWARDED_IP = "203.0.113.7";
const SOCKET_IP = "198.51.100.9";
const FALLBACK = "US or Europe (EU)";

function fixture(
  fncp = false,
  options: {
    promptFailure?: boolean;
    strict?: boolean;
    seed?: boolean;
    moderator?: boolean;
  } = {}
) {
  const logger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };
  const generateContent: any = jest.fn(async () => ({
    text: JSON.stringify({ output: { final_score: "5", trace: MODEL_TRACE } }),
  }));
  const query: any = jest.fn(async (sql: string) =>
    /INSERT INTO COMMENTS/u.test(sql) ? [{ tid: 73019, created: 1000 }] : []
  );
  const getRoles: any = jest.fn(async () => ({
    data: [{ name: "delphi-enabled" }],
  }));
  const getUser: any = jest.fn(async () => ({ email: OWNER_EMAIL }));
  const detectLanguage: any = jest.fn(async () => [
    { language: "en", confidence: 1 },
  ]);
  const parse: any = jest.fn((_name: string, value: unknown) =>
    JSON.stringify(value)
  );
  const readFile: any = jest.fn(async () => {
    if (options.promptFailure) throw new Error(COMMENT + MODEL_TRACE);
    return "invented prompt source";
  });
  const isModerator: any = jest.fn(async () => options.moderator ?? false);
  const executeQuery: any = jest.fn(
    (_sql: string, _params: unknown[], callback: any) =>
      callback(null, { rows: [] })
  );
  const readOnlyQuery: any = jest.fn(
    (_sql: string, _params: unknown[], callback: any) =>
      callback(null, { rows: [{ count: 0 }] })
  );
  const convertXML: any = jest.fn(async () => ({
    polis_moderation_rubric: {
      children: Array.from({ length: 12 }, () => ({
        task: { children: [{}, {}] },
      })),
    },
  }));
  jest.doMock("../../src/config", () => ({
    __esModule: true,
    default: {
      freshBootstrapLocalOnly: false,
      geminiApiKey: "invented-key",
      shouldUseTranslationAPI: false,
    },
  }));
  jest.doMock("../../src/utils/logger", () => ({
    __esModule: true,
    default: logger,
  }));
  jest.doMock("fs/promises", () => ({
    __esModule: true,
    default: { readFile },
  }));
  jest.doMock("simple-xml-to-json", () => ({ convertXML }));
  jest.doMock("js2xmlparser", () => ({ parse }));
  jest.doMock("@google/genai", () => ({
    GoogleGenAI: jest.fn(function () {
      return { models: { generateContent } };
    }),
  }));
  jest.doMock("auth0", () => ({
    ManagementClient: jest.fn(function () {
      return {
        usersByEmail: {
          getByEmail: jest.fn(async () => ({
            data: [{ user_id: OWNER_SUBJECT }],
          })),
        },
        users: { getRoles },
      };
    }),
  }));
  jest.doMock("../../src/db/pg-query", () => ({
    __esModule: true,
    default: {
      queryP: query,
      queryP_readOnly: query,
      query: executeQuery,
      query_readOnly: readOnlyQuery,
    },
  }));
  jest.doMock("../../src/conversation", () => ({
    getConversationInfo: jest.fn(async () => ({
      owner: 81017,
      is_active: true,
      strict_moderation: options.strict ?? false,
      profanity_filter: true,
      topic: TOPIC,
    })),
  }));
  jest.doMock("../../src/user", () => ({
    getUserInfoForUid2: getUser,
    getPidPromise: jest.fn(async () => 91017),
  }));
  jest.doMock("../../src/participant", () => ({ addParticipant: jest.fn() }));
  jest.doMock("../../src/utils/common", () => ({
    isModerator,
    polisTypes: { mod: { ok: 1, unmoderated: 0 } },
  }));
  jest.doMock("../../src/comment", () => ({ detectLanguage }));
  jest.doMock("../../src/routes/votes", () => ({ votesPost: jest.fn() }));
  jest.doMock("../../src/server-helpers", () => ({
    safeTimestampToMillis: (value: number) => value,
    updateConversationModifiedTime: jest.fn(),
    updateLastInteractionTimeForConversation: jest.fn(),
    updateVoteCount: jest.fn(),
    sendEmailByUid: jest.fn(),
  }));
  jest.doMock("../../src/utils/zinvite", () => ({}));
  jest.doMock("../../src/utils/metered", () => ({
    MPromise: (_label: string, executor: any) => new Promise(executor),
  }));
  jest.doMock("../../src/nextComment", () => ({}));
  jest.doMock("../../src/utils/pagination", () => ({}));
  const policy: any = jest.requireActual(
    "../../src/auth/fncp-participant-policy"
  );
  jest.doMock("../../src/auth/fncp-participant-policy", () => ({
    fncpParticipantProcessingPolicy: (req: any) =>
      policy.fncpParticipantProcessingPolicy(req, {
        FNCP_GATEWAY_CONVERSATION_ID: fncp ? CONVERSATION : "",
      }),
  }));
  const moderation = require("../../src/utils/moderation");
  const {
    handle_POST_comments,
    handle_PUT_comments,
    isProConvo,
  } = require("../../src/routes/comments");
  const fetch = jest
    .spyOn(globalThis, "fetch")
    .mockRejectedValue(new Error("NETWORK_DISABLED"));
  async function post(headers: Record<string, string> = {}) {
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    await handle_POST_comments(
      {
        p: {
          zid: 71017,
          uid: 81017,
          pid: 91017,
          txt: COMMENT,
          is_seed: options.seed ?? false,
        },
        body: { conversation_id: CONVERSATION },
        headers,
        socket: { remoteAddress: SOCKET_IP },
        connection: { remoteAddress: SOCKET_IP },
      },
      res
    );
    return res;
  }
  const logs = () =>
    JSON.stringify(Object.values(logger).flatMap((fn) => fn.mock.calls));
  const insertedState = () => {
    const call = query.mock.calls.find(([sql]: [string]) =>
      /INSERT INTO COMMENTS/u.test(sql)
    );
    return call ? { active: call[1][4], mod: call[1][5] } : null;
  };
  async function approve() {
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const completed = new Promise<void>((resolve) =>
      res.json.mockImplementation(() => resolve())
    );
    handle_PUT_comments(
      {
        p: {
          uid: 81017,
          zid: 71017,
          tid: 73019,
          active: true,
          mod: 1,
          is_meta: false,
        },
      },
      res
    );
    await completed;
    return res;
  }
  return {
    moderation,
    isProConvo,
    generateContent,
    query,
    getRoles,
    getUser,
    detectLanguage,
    parse,
    fetch,
    logger,
    post,
    logs,
    insertedState,
    approve,
    isModerator,
    executeQuery,
    readFile,
  };
}

beforeEach(() => {
  jest.resetModules();
  jest.useFakeTimers();
});
afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
  jest.restoreAllMocks();
  jest.resetModules();
});

function expectPrivateLogsAbsent(h: ReturnType<typeof fixture>) {
  for (const value of [
    COMMENT,
    TOPIC,
    MODEL_TRACE,
    OWNER_EMAIL,
    OWNER_SUBJECT,
    FORWARDED_IP,
    SOCKET_IP,
    "71017",
    "81017",
    "91017",
  ])
    expect(h.logs()).not.toContain(value);
}

test.each([
  {},
  { "x-forwarded-for": FORWARDED_IP },
  { "x-forwarded-for": FORWARDED_IP + ", " + SOCKET_IP },
])(
  "real optional moderation uses the unchanged fallback without address transport (%j)",
  async (headers) => {
    const h = fixture();
    await h.moderation.moderationReady;
    const res = await h.post(headers);
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ tid: 73019, currentPid: 91017 });
    expect(h.fetch).not.toHaveBeenCalled();
    expect(h.generateContent).toHaveBeenCalledTimes(1);
    const input =
      h.parse.mock.calls[0][1].polis_moderation_rubric.children[11].task
        .children[1].input;
    expect(input).toEqual({
      comment_text: COMMENT,
      conversation_topic: TOPIC,
      geographical_context: FALLBACK,
    });
    const prompt = h.generateContent.mock.calls[0][0].contents[0].parts[0].text;
    expect(prompt).not.toContain(FORWARDED_IP);
    expect(prompt).not.toContain(SOCKET_IP);
    expectPrivateLogsAbsent(h);
  }
);

test("a model failure containing private fixture text produces only a fixed diagnostic", async () => {
  const h = fixture();
  await h.moderation.moderationReady;
  h.generateContent.mockRejectedValue(
    new Error(COMMENT + FORWARDED_IP + MODEL_TRACE)
  );
  const res = await h.post({ "x-forwarded-for": FORWARDED_IP });
  expect(res.status).not.toHaveBeenCalled();
  expect(h.fetch).not.toHaveBeenCalled();
  expect(h.logger.error).toHaveBeenCalledWith(
    "polis_moderation_analysis_unavailable"
  );
  expect(h.insertedState()).toEqual({ active: false, mod: 0 });
  expectPrivateLogsAbsent(h);
});

test("malformed model output never enters logs and enters manual hold", async () => {
  const h = fixture();
  await h.moderation.moderationReady;
  h.generateContent.mockResolvedValue({ text: MODEL_TRACE + "{invalid JSON" });
  const res = await h.post();
  expect(res.status).not.toHaveBeenCalled();
  expect(h.fetch).not.toHaveBeenCalled();
  expect(h.insertedState()).toEqual({ active: false, mod: 0 });
  expectPrivateLogsAbsent(h);
});

test("failed eager prompt loading is handled before any caller and retains Promise<void>", async () => {
  jest.useRealTimers();
  const unhandled: unknown[] = [];
  const observe = (error: unknown) => unhandled.push(error);
  process.on("unhandledRejection", observe);
  try {
    const h = fixture(false, { promptFailure: true });
    await new Promise<void>((resolve) => setImmediate(resolve));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(unhandled).toEqual([]);
    await expect(h.moderation.moderationReady).resolves.toBeUndefined();
    expect(h.generateContent).not.toHaveBeenCalled();
    expect(h.parse).not.toHaveBeenCalled();
    expect(h.logger.error).not.toHaveBeenCalled();
    jest.useFakeTimers();
    const res = await h.post();
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ tid: 73019, currentPid: 91017 });
    expect(h.insertedState()).toEqual({ active: false, mod: 0 });
    expect(h.generateContent).not.toHaveBeenCalled();
    expect(h.fetch).not.toHaveBeenCalled();
    expectPrivateLogsAbsent(h);
  } finally {
    process.off("unhandledRejection", observe);
  }
});

const invalidScores: [string, unknown][] = [
  ["missing", undefined],
  ["null", null],
  ["false", false],
  ["true", true],
  ["empty string", ""],
  ["whitespace", "  "],
  ["array", []],
  ["numeric array", [5]],
  ["object", {}],
  ["negative number", -1],
  ["negative string", "-1"],
  ["positive infinity", "Infinity"],
  ["negative infinity", "-Infinity"],
  ["NaN", "NaN"],
  ["hexadecimal", "0x10"],
  ["unknown text", "unavailable"],
];
test.each(
  invalidScores.flatMap(([name, raw]) =>
    [false, true].map((strict) => [name, strict, raw] as const)
  )
)(
  "invalid %s score is a stored HTTP receipt and manual hold, strict=%s",
  async (_name, strict, raw) => {
    const h = fixture(false, { strict });
    await h.moderation.moderationReady;
    h.generateContent.mockResolvedValue({
      text: JSON.stringify({ output: { final_score: raw } }),
    });
    const res = await h.post();
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ tid: 73019, currentPid: 91017 });
    expect(h.insertedState()).toEqual({ active: false, mod: 0 });
    expect(h.fetch).not.toHaveBeenCalled();
    expectPrivateLogsAbsent(h);
  }
);

test.each(["1e309", "-1e309"])(
  "overflowing JSON number %s is held without automatic banning",
  async (value) => {
    const h = fixture();
    await h.moderation.moderationReady;
    h.generateContent.mockResolvedValue({
      text: '{"output":{"final_score":' + value + "}}",
    });
    await h.post();
    expect(h.insertedState()).toEqual({ active: false, mod: 0 });
    expectPrivateLogsAbsent(h);
  }
);

const validScores: [unknown, number][] = [
  [0, 0],
  [37.5, 37.5],
  [99.5, 99.5],
  [100, 100],
  [150, 150],
  ["0", 0],
  ["37.5", 37.5],
  ["99.5", 99.5],
  ["100", 100],
  ["1e2", 100],
];
test.each(
  validScores.flatMap(([raw, numeric]) =>
    [false, true].map((strict) => [raw, numeric, strict] as const)
  )
)(
  "valid score %s preserves the numeric threshold %s, strict=%s",
  async (raw, numeric, strict) => {
    const h = fixture(false, { strict });
    await h.moderation.moderationReady;
    h.generateContent.mockResolvedValue({
      text: JSON.stringify({ output: { final_score: raw } }),
    });
    const res = await h.post();
    expect(res.status).not.toHaveBeenCalled();
    expect(h.insertedState()).toEqual(
      numeric >= 100 ? { active: false, mod: -1 } : { active: true, mod: 0 }
    );
    expect(h.fetch).not.toHaveBeenCalled();
    expectPrivateLogsAbsent(h);
  }
);

test.each(["5", null, false, NaN, Infinity, -Infinity, -1])(
  "decision boundary refuses unchecked/coercible module result %s",
  async (raw) => {
    const h = fixture();
    await h.moderation.moderationReady;
    jest.spyOn(h.moderation, "default").mockResolvedValue(raw);
    await h.post();
    expect(h.insertedState()).toEqual({ active: false, mod: 0 });
    expect(h.generateContent).not.toHaveBeenCalled();
    expect(h.fetch).not.toHaveBeenCalled();
  }
);

test("existing authorized moderator action can release an unavailable-result manual hold", async () => {
  const h = fixture();
  await h.moderation.moderationReady;
  h.generateContent.mockResolvedValue({ text: "{invalid" });
  await h.post();
  expect(h.insertedState()).toEqual({ active: false, mod: 0 });
  expectPrivateLogsAbsent(h);
  h.isModerator.mockResolvedValue(true);
  const res = await h.approve();
  expect(res.status).toHaveBeenCalledWith(200);
  expect(h.executeQuery).toHaveBeenCalledWith(
    "UPDATE comments SET active = $1, mod = $2, is_meta = $3 WHERE zid = $4 AND tid = $5",
    [true, 1, false, 71017, 73019],
    expect.any(Function)
  );
  expect(res.json).toHaveBeenCalledWith({});
});

test("an unauthorized moderator action cannot release the held comment", async () => {
  const h = fixture();
  const res = await h.approve();
  expect(res.status).toHaveBeenCalledWith(403);
  expect(h.executeQuery).not.toHaveBeenCalled();
});

test.each([
  { seed: true, moderator: false },
  { seed: false, moderator: true },
])("existing seed/moderator exemption remains intact (%j)", async (options) => {
  const h = fixture(false, options);
  await h.moderation.moderationReady;
  const res = await h.post();
  expect(res.status).not.toHaveBeenCalled();
  expect(h.insertedState()).toEqual({ active: true, mod: 1 });
  expect(h.generateContent).not.toHaveBeenCalled();
  expect(h.getUser).not.toHaveBeenCalled();
  expect(h.fetch).not.toHaveBeenCalled();
  expectPrivateLogsAbsent(h);
});

test.each(["23505", "23503", "unclassified"])(
  "comment-write failure keeps its error code without logging raw fixture errors (%s)",
  async (code) => {
    const h = fixture();
    await h.moderation.moderationReady;
    const error = Object.assign(
      new Error(COMMENT + OWNER_EMAIL + FORWARDED_IP),
      {
        code,
        constraint: "invented_constraint",
        detail: MODEL_TRACE,
      }
    );
    h.query.mockImplementation(async (sql: string) => {
      if (/INSERT INTO COMMENTS/u.test(sql)) throw error;
      return [];
    });
    const res = await h.post();
    expect(res.status).toHaveBeenCalledWith(code === "23505" ? 409 : 500);
    expect(h.logger.error).toHaveBeenCalledWith("Comment creation failed");
    expectPrivateLogsAbsent(h);
    expect(h.fetch).not.toHaveBeenCalled();
  }
);

test("owner role lookup errors do not log addresses, subjects or raw exceptions", async () => {
  const h = fixture();
  h.getRoles.mockRejectedValue(
    new Error(OWNER_EMAIL + OWNER_SUBJECT + MODEL_TRACE)
  );
  await expect(h.isProConvo(81017)).resolves.toBe(false);
  expect(h.logger.error).toHaveBeenCalledWith(
    "polis_moderation_owner_lookup_unavailable"
  );
  expectPrivateLogsAbsent(h);
});

test("FNCP policy still bypasses external moderation and language/owner lookup", async () => {
  const h = fixture(true);
  await h.moderation.moderationReady;
  const res = await h.post({ "x-forwarded-for": FORWARDED_IP });
  expect(res.status).not.toHaveBeenCalled();
  expect(h.generateContent).not.toHaveBeenCalled();
  expect(h.getUser).not.toHaveBeenCalled();
  expect(h.detectLanguage).not.toHaveBeenCalled();
  expect(h.fetch).not.toHaveBeenCalled();
  expectPrivateLogsAbsent(h);
});

test("server source cannot reintroduce the removed third-party geolocation service", () => {
  const root = resolve(__dirname, "../../src");
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory()
        ? walk(join(dir, entry.name))
        : [join(dir, entry.name)]
    );
  const files = walk(root);
  expect(files.length).toBeGreaterThan(100);
  expect(
    files.filter((file) => /ip-api\.com/iu.test(readFileSync(file, "utf8")))
  ).toEqual([]);
});
