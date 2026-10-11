import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from "@jest/globals";

// Only the four subject modules execute. Their application dependencies are
// explicit test doubles: no app, actual Config, DB pool, SDK or network import.
function harness(fresh: boolean, overrides: Record<string, unknown> = {}) {
  const config: any = {
    freshBootstrapLocalOnly: fresh,
    isDevMode: false,
    adminEmails: "[]",
    polisFromAddress: "sender@example.invalid",
    getServerUrl: jest.fn(() => "https://bootstrap.example.invalid"),
    akismetAntispamApiKey: "synthetic-akismet-key",
    authDomain: "synthetic-auth.example.invalid",
    authClientId: "synthetic-client",
    authClientSecret: "synthetic-secret",
    awsRegion: "synthetic-region",
    SESEndpoint: "https://ses.example.invalid",
    awsAccessKeyId: "synthetic-access",
    awsSecretAccessKey: "synthetic-secret",
    ...overrides,
  };
  const logger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };
  const queryP: any = jest.fn(async () => []);
  const pg = { queryP, query: jest.fn(), queryP_readOnly: jest.fn() };
  const send: any = jest.fn(async () => ({ MessageId: "synthetic-message" }));
  const sesConstructor = jest.fn(function () {
    return { send };
  });
  const commandConstructor = jest.fn(function (params: unknown) {
    return { params };
  });
  const verifyKey = jest.fn(
    (callback: (error: unknown, verified: boolean) => void) =>
      callback(null, true)
  );
  const akismetConstructor = jest.fn(() => ({ verifyKey }));
  const getUser: any = jest.fn(async () => ({
    email: "owner@example.invalid",
  }));
  const getByEmail: any = jest.fn(async () => ({
    data: [{ user_id: "synthetic-owner" }],
  }));
  const getRoles: any = jest.fn(async () => ({
    data: [{ name: "delphi-enabled" }],
  }));
  const managementConstructor = jest.fn(function () {
    return { usersByEmail: { getByEmail }, users: { getRoles } };
  });
  jest.doMock("../../src/config", () => ({
    __esModule: true,
    default: config,
  }));
  jest.doMock("../../src/utils/logger", () => ({
    __esModule: true,
    default: logger,
  }));
  jest.doMock("../../src/db/pg-query", () => ({
    __esModule: true,
    default: pg,
  }));
  jest.doMock("@aws-sdk/client-sesv2", () => ({
    SESv2Client: sesConstructor,
    SendEmailCommand: commandConstructor,
  }));
  jest.doMock("akismet", () => ({
    __esModule: true,
    default: { client: akismetConstructor },
  }));
  jest.doMock("auth0", () => ({ ManagementClient: managementConstructor }));
  jest.doMock("bluebird", () => ({
    Promise: {
      longStackTraces: jest.fn(),
      onPossiblyUnhandledRejection: jest.fn(),
    },
  }));
  jest.doMock("../../src/utils/metered", () => ({
    METRICS_IN_RAM: {},
    MPromise: jest.fn(),
  }));
  jest.doMock("../../src/auth", () => ({
    generateAndRegisterZinvite: jest.fn(),
  }));
  jest.doMock("../../src/utils/fail", () => ({ failJson: jest.fn() }));
  jest.doMock("../../src/utils/pca", () => ({
    fetchAndCacheLatestPcaData: jest.fn(),
  }));
  jest.doMock("../../src/utils/participants", () => ({
    getPidsForGid: jest.fn(),
  }));
  jest.doMock("../../src/utils/file-fetcher", () => ({
    fetchIndex: jest.fn(),
    makeFileFetcher: jest.fn(),
  }));
  jest.doMock("../../src/server-helpers", () => ({
    sendEmailByUid: jest.fn(),
  }));
  jest.doMock("../../src/comment", () => ({ detectLanguage: jest.fn() }));
  jest.doMock("../../src/conversation", () => ({
    getConversationInfo: jest.fn(),
  }));
  jest.doMock("../../src/utils/zinvite", () => ({ getZinvite: jest.fn() }));
  jest.doMock("../../src/utils/common", () => ({ isPolisDev: jest.fn() }));
  jest.doMock("../../src/utils/csv-records", () => ({
    parseCsvRecords: jest.fn(),
  }));
  jest.doMock("../../src/participant", () => ({ addParticipant: jest.fn() }));
  jest.doMock("../../src/nextComment", () => ({ getNextComment: jest.fn() }));
  jest.doMock("../../src/user", () => ({
    getUserInfoForUid2: getUser,
    getPidPromise: jest.fn(),
  }));
  jest.doMock("../../src/routes/votes", () => ({ votesPost: jest.fn() }));
  jest.doMock("../../src/utils/moderation", () => ({
    __esModule: true,
    default: jest.fn(),
  }));
  jest.doMock("../../src/utils/pagination", () => ({
    parsePagination: jest.fn(),
    createPaginationMeta: jest.fn(),
  }));
  jest.doMock("../../src/auth/fncp-participant-policy", () => ({
    fncpParticipantProcessingPolicy: jest.fn(),
  }));
  return {
    config,
    logger,
    pg,
    send,
    sesConstructor,
    commandConstructor,
    verifyKey,
    akismetConstructor,
    getUser,
    getByEmail,
    getRoles,
    managementConstructor,
  };
}

function noLogs(logger: ReturnType<typeof harness>["logger"]) {
  for (const call of Object.values(logger)) expect(call).not.toHaveBeenCalled();
}

describe("fresh bootstrap side-effect boundaries (mocked modules only)", () => {
  beforeEach(() => {
    jest.resetModules();
    jest.useFakeTimers();
  });
  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
    jest.resetModules();
  });

  test("fresh server import never constructs Akismet, even with a synthetic key", () => {
    const h = harness(true);
    require("../../src/server");
    expect(h.akismetConstructor).not.toHaveBeenCalled();
    expect(h.verifyKey).not.toHaveBeenCalled();
    expect(h.sesConstructor).not.toHaveBeenCalled();
    expect(h.pg.queryP).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
    noLogs(h.logger);
  });

  test.each([null, "", undefined])(
    "ordinary server does not verify an absent Akismet key (%s)",
    (key) => {
      const h = harness(false, { akismetAntispamApiKey: key });
      require("../../src/server");
      expect(h.akismetConstructor).not.toHaveBeenCalled();
      expect(h.verifyKey).not.toHaveBeenCalled();
    }
  );

  test("ordinary configured Akismet construction and verification are preserved", () => {
    const h = harness(false);
    require("../../src/server");
    expect(h.akismetConstructor).toHaveBeenCalledTimes(1);
    expect(h.akismetConstructor).toHaveBeenCalledWith({
      blog: "https://bootstrap.example.invalid",
      apiKey: "synthetic-akismet-key",
    });
    expect(h.verifyKey).toHaveBeenCalledTimes(1);
    expect(h.logger.debug).toHaveBeenCalledWith(
      "Akismet: API key successfully verified."
    );
  });

  test("fresh production notification import neither claims tasks nor schedules a loop", async () => {
    const h = harness(true);
    require("../../src/routes/notify");
    await Promise.resolve();
    expect(h.pg.queryP).not.toHaveBeenCalled();
    expect(h.sesConstructor).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
    noLogs(h.logger);
  });

  test("ordinary development mode still leaves notifications stopped", () => {
    const h = harness(false, { isDevMode: true });
    require("../../src/routes/notify");
    expect(h.pg.queryP).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
  });

  test("ordinary production notification scheduling remains intact against the fake DB", async () => {
    const h = harness(false);
    require("../../src/routes/notify");
    await jest.advanceTimersByTimeAsync(0);
    expect(h.pg.queryP).toHaveBeenCalledTimes(1);
    expect(h.pg.queryP.mock.calls[0][0]).toContain(
      "delete from notification_tasks"
    );
    expect(jest.getTimerCount()).toBe(1);
    expect(h.sesConstructor).not.toHaveBeenCalled();
  });

  test.each(["sendTextEmail", "sendMultipleTextEmails", "emailTeam"])(
    "fresh %s rejects before any client, command, argument traversal or log",
    async (entry) => {
      const h = harness(true);
      const recipientRead = jest.fn(() => {
        throw new Error("private recipient must not be read");
      });
      const forbiddenRecipients = new Proxy([], { get: recipientRead });
      const adminRead = jest.fn(() => {
        throw new Error("private configuration must not be read");
      });
      Object.defineProperty(h.config, "adminEmails", { get: adminRead });
      const sender = require("../../src/email/senders");
      const args =
        entry === "emailTeam"
          ? ["synthetic subject", "synthetic body"]
          : [
              "sender@example.invalid",
              entry === "sendMultipleTextEmails"
                ? forbiddenRecipients
                : "recipient@example.invalid",
              "synthetic subject",
              "synthetic body",
            ];
      await expect(sender[entry](...args)).rejects.toThrow(
        "polis_err_fncp_fresh_bootstrap_email_disabled"
      );
      expect(recipientRead).not.toHaveBeenCalled();
      expect(adminRead).not.toHaveBeenCalled();
      expect(h.sesConstructor).not.toHaveBeenCalled();
      expect(h.commandConstructor).not.toHaveBeenCalled();
      expect(h.send).not.toHaveBeenCalled();
      noLogs(h.logger);
    }
  );

  test("fresh bulk email rejects even an empty recipient list instead of pretending success", async () => {
    const h = harness(true);
    const { sendMultipleTextEmails } = require("../../src/email/senders");
    await expect(
      sendMultipleTextEmails("sender@example.invalid", [], "subject", "body")
    ).rejects.toThrow("polis_err_fncp_fresh_bootstrap_email_disabled");
    expect(h.sesConstructor).not.toHaveBeenCalled();
    noLogs(h.logger);
  });

  test("ordinary email imports are lazy and configured sends reuse their synthetic client", async () => {
    const h = harness(false);
    const { sendTextEmail } = require("../../src/email/senders");
    expect(h.sesConstructor).not.toHaveBeenCalled();
    await expect(
      sendTextEmail(
        "sender@example.invalid",
        "recipient@example.invalid",
        "subject",
        "body"
      )
    ).resolves.toEqual({ MessageId: "synthetic-message" });
    await sendTextEmail(
      "sender@example.invalid",
      "recipient@example.invalid",
      "subject",
      "body"
    );
    expect(h.sesConstructor).toHaveBeenCalledTimes(1);
    expect(h.sesConstructor).toHaveBeenCalledWith({
      region: "synthetic-region",
      endpoint: "https://ses.example.invalid",
      credentials: {
        accessKeyId: "synthetic-access",
        secretAccessKey: "synthetic-secret",
      },
    });
    expect(h.commandConstructor).toHaveBeenCalledTimes(2);
    expect(h.send).toHaveBeenCalledTimes(2);
  });

  test("ordinary team email still dispatches the configured recipients", async () => {
    const h = harness(false, {
      adminEmails: '["one@example.invalid","two@example.invalid"]',
    });
    const { emailTeam } = require("../../src/email/senders");
    await emailTeam("subject", "body");
    expect(h.send).toHaveBeenCalledTimes(2);
    expect(
      h.commandConstructor.mock.calls.map(
        ([params]: any[]) => params.Destination.ToAddresses
      )
    ).toEqual([["one@example.invalid"], ["two@example.invalid"]]);
    noLogs(h.logger);
  });

  test("an already cached SES client cannot bypass a later deny state", async () => {
    const h = harness(false);
    const { sendTextEmail } = require("../../src/email/senders");
    await sendTextEmail(
      "sender@example.invalid",
      "recipient@example.invalid",
      "subject",
      "body"
    );
    h.config.freshBootstrapLocalOnly = true;
    await expect(
      sendTextEmail(
        "sender@example.invalid",
        "recipient@example.invalid",
        "subject",
        "body"
      )
    ).rejects.toThrow("polis_err_fncp_fresh_bootstrap_email_disabled");
    expect(h.send).toHaveBeenCalledTimes(1);
    expect(h.commandConstructor).toHaveBeenCalledTimes(1);
  });

  test.each([true, false])(
    "comments import is lazy for Auth0 when fresh=%s",
    (fresh) => {
      const h = harness(fresh);
      require("../../src/routes/comments");
      expect(h.managementConstructor).not.toHaveBeenCalled();
      expect(h.getUser).not.toHaveBeenCalled();
      expect(h.pg.queryP).not.toHaveBeenCalled();
      noLogs(h.logger);
    }
  );

  test("fresh Auth0 lookup rejects before owner data, external client, or logging", async () => {
    const h = harness(true);
    const { isProConvo } = require("../../src/routes/comments");
    await expect(isProConvo(71)).rejects.toThrow(
      "polis_err_fncp_fresh_bootstrap_auth0_management_disabled"
    );
    expect(h.managementConstructor).not.toHaveBeenCalled();
    expect(h.getUser).not.toHaveBeenCalled();
    expect(h.getByEmail).not.toHaveBeenCalled();
    expect(h.getRoles).not.toHaveBeenCalled();
    noLogs(h.logger);
  });

  test("ordinary Pro role lookup constructs once only when used", async () => {
    const h = harness(false);
    const { isProConvo } = require("../../src/routes/comments");
    expect(h.managementConstructor).not.toHaveBeenCalled();
    await expect(isProConvo(71)).resolves.toBe(true);
    await expect(isProConvo(71)).resolves.toBe(true);
    expect(h.managementConstructor).toHaveBeenCalledTimes(1);
    expect(h.managementConstructor).toHaveBeenCalledWith({
      domain: "synthetic-auth.example.invalid",
      clientId: "synthetic-client",
      clientSecret: "synthetic-secret",
    });
    expect(h.getByEmail).toHaveBeenCalledWith({
      email: "owner@example.invalid",
    });
    expect(h.getRoles).toHaveBeenCalledWith({ id: "synthetic-owner" });
  });

  test("ordinary missing-owner-email result does not initialize Auth0", async () => {
    const h = harness(false);
    h.getUser.mockResolvedValue({});
    const { isProConvo } = require("../../src/routes/comments");
    await expect(isProConvo(71)).resolves.toBe(false);
    expect(h.managementConstructor).not.toHaveBeenCalled();
  });

  test("a cached Auth0 client cannot bypass a later deny state", async () => {
    const h = harness(false);
    const { isProConvo } = require("../../src/routes/comments");
    await expect(isProConvo(71)).resolves.toBe(true);
    h.config.freshBootstrapLocalOnly = true;
    await expect(isProConvo(71)).rejects.toThrow(
      "polis_err_fncp_fresh_bootstrap_auth0_management_disabled"
    );
    expect(h.getUser).toHaveBeenCalledTimes(1);
    expect(h.getByEmail).toHaveBeenCalledTimes(1);
    expect(h.getRoles).toHaveBeenCalledTimes(1);
  });
});
