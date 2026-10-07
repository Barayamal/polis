import { describe, expect, test } from "@jest/globals";
import express from "express";
import request from "supertest";

import {
  createCookieParser,
  createJsonBodyParser,
  createResponseCompression,
  createUrlencodedBodyParser,
  rejectUnsupportedMultipart,
} from "../../src/http-middleware";

function createTestApp() {
  const app = express();
  app.use(rejectUnsupportedMultipart);
  app.use(createJsonBodyParser());
  app.use(createUrlencodedBodyParser());
  app.use(createCookieParser());
  app.use(createResponseCompression());

  app.post("/inspect", (req, res) => {
    res.json({
      body: req.body,
      cookie: req.cookies?.fncp,
    });
  });

  app.get("/compress", (_req, res) => {
    res.type("text/plain").send("First Nations Community Pulse ".repeat(200));
  });

  return app;
}

describe("supported Express HTTP middleware", () => {
  test("parses standard and structured-suffix JSON", async () => {
    const app = createTestApp();
    const payload = { conversation_id: "fncp-test", xid: "opaque-123" };

    for (const contentType of [
      "application/json",
      "application/vnd.fncp+json",
    ]) {
      const response = await request(app)
        .post("/inspect")
        .set("Content-Type", contentType)
        .send(JSON.stringify(payload));

      expect(response.status).toBe(200);
      expect(response.body.body).toEqual(payload);
    }
  });

  test("preserves nested urlencoded fields and parses cookies", async () => {
    const app = createTestApp();
    const response = await request(app)
      .post("/inspect")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .set("Cookie", "fncp=opaque-session")
      .send("participant[choice]=agree&participant[round]=1");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      body: {
        participant: {
          choice: "agree",
          round: "1",
        },
      },
      cookie: "opaque-session",
    });
  });

  test("rejects unsupported multipart bodies without a legacy temp-file parser", async () => {
    const app = createTestApp();
    const response = await request(app)
      .post("/inspect")
      .field("conversation_id", "fncp-test");

    expect(response.status).toBe(415);
    expect(response.body).toEqual({
      error: "polis_err_multipart_not_supported",
      message: "polis_err_multipart_not_supported",
      status: 415,
    });
  });

  test("preserves duplicate fields, arrays and sparse indices with the patched qs parser", async () => {
    const response = await request(createTestApp())
      .post("/inspect")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("choice=agree&choice=pass&rounds[]=one&rounds[]=two&nested[round]=test&items[999999]=sparse");

    expect(response.status).toBe(200);
    expect(response.body.body).toEqual({
      choice: ["agree", "pass"],
      rounds: ["one", "two"],
      nested: { round: "test" },
      items: { "999999": "sparse" },
    });
  });

  test("does not turn prototype-shaped form fields into inherited properties", async () => {
    const response = await request(createTestApp())
      .post("/inspect")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("__proto__[fncp_polluted]=yes&constructor[prototype][fncp_polluted]=yes&safe=retained");

    expect(response.status).toBe(200);
    expect(response.body.body.safe).toBe("retained");
    expect(Object.prototype.hasOwnProperty.call(response.body.body, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, "fncp_polluted")).toBe(false);
    expect(({} as Record<string, unknown>).fncp_polluted).toBeUndefined();
  });

  test("keeps isBuffer-shaped nested input as ordinary form data", async () => {
    const response = await request(createTestApp())
      .post("/inspect")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("constructor[isBuffer]=not-a-function&record[isBuffer]=false&record[value]=test");

    expect(response.status).toBe(200);
    expect(response.body.body.record).toEqual({ isBuffer: "false", value: "test" });
  });

  test("compresses eligible responses", async () => {
    const app = createTestApp();
    const response = await request(app)
      .get("/compress")
      .set("Accept-Encoding", "gzip");

    expect(response.status).toBe(200);
    expect(response.headers["content-encoding"]).toBe("gzip");
    expect(response.text).toContain("First Nations Community Pulse");
  });
});
