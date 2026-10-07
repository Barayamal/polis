import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";

import { afterEach, describe, expect, jest, test } from "@jest/globals";
import express from "express";
import request from "supertest";

import {
  globalErrorHandler,
  requestTimeout,
} from "../../src/server-middleware";

type TimeoutError = Error & {
  code?: string;
  timeout?: number;
  status?: number;
  statusCode?: number;
};

function makeRequest() {
  const req = new EventEmitter() as EventEmitter & {
    path: string;
    body: Record<string, never>;
    method: string;
    originalUrl: string;
    timedout?: boolean;
    clearTimeout?: () => void;
  };
  req.path = "/api/v3/nextComment";
  req.body = {};
  req.method = "GET";
  req.originalUrl = "/api/v3/nextComment";
  return req;
}

function makeResponse() {
  const res = new EventEmitter() as EventEmitter & {
    headersSent: boolean;
    writableEnded: boolean;
    statusCode: number;
  };
  res.headersSent = false;
  res.writableEnded = false;
  res.statusCode = 200;
  return res;
}

afterEach(() => {
  jest.useRealTimers();
});

describe("requestTimeout", () => {
  test("preserves the exact 15-second ETIMEDOUT contract", () => {
    jest.useFakeTimers();
    const req = makeRequest();
    const res = makeResponse();
    const next = jest.fn<(error?: TimeoutError) => void>();
    const emitted: number[] = [];
    req.on("timeout", (delay) => emitted.push(delay));

    requestTimeout(15_000)(req as never, res as never, next);

    expect(req.timedout).toBe(false);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenLastCalledWith();

    jest.advanceTimersByTime(14_999);
    expect(next).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(1);
    expect(req.timedout).toBe(true);
    expect(emitted).toEqual([15_000]);
    expect(next).toHaveBeenCalledTimes(2);
    expect(next.mock.calls[1][0]).toMatchObject({
      message: "Response timeout",
      code: "ETIMEDOUT",
      timeout: 15_000,
      status: 503,
      statusCode: 503,
    });
  });

  test.each(["finish", "close"] as const)(
    "cancels the timeout when the response emits %s",
    (eventName) => {
      jest.useFakeTimers();
      const req = makeRequest();
      const res = makeResponse();
      const next = jest.fn<(error?: TimeoutError) => void>();

      requestTimeout(15_000)(req as never, res as never, next);
      res.emit(eventName);
      jest.advanceTimersByTime(15_000);

      expect(req.timedout).toBe(false);
      expect(next).toHaveBeenCalledTimes(1);
    }
  );

  test("does not emit a late timeout after headers have been sent", () => {
    jest.useFakeTimers();
    const req = makeRequest();
    const res = makeResponse();
    const next = jest.fn<(error?: TimeoutError) => void>();

    requestTimeout(15_000)(req as never, res as never, next);
    res.headersSent = true;
    jest.advanceTimersByTime(15_000);

    expect(req.timedout).toBe(false);
    expect(next).toHaveBeenCalledTimes(1);
  });

  test("retains the request clearTimeout escape hatch", () => {
    jest.useFakeTimers();
    const req = makeRequest();
    const res = makeResponse();
    const next = jest.fn<(error?: TimeoutError) => void>();

    requestTimeout(15_000)(req as never, res as never, next);
    expect(req.clearTimeout).toEqual(expect.any(Function));
    req.clearTimeout?.();
    jest.advanceTimersByTime(15_000);

    expect(req.timedout).toBe(false);
    expect(next).toHaveBeenCalledTimes(1);
  });
});

describe("globalErrorHandler timeout response", () => {
  test("maps the native ETIMEDOUT error to the established 408 JSON body", () => {
    const req = makeRequest();
    const json = jest.fn();
    const status = jest.fn(() => ({ json }));
    const res = {
      statusCode: 200,
      headersSent: false,
      status,
    };
    const next = jest.fn();
    const error = Object.assign(new Error("Response timeout"), {
      code: "ETIMEDOUT",
      timeout: 15_000,
      status: 503,
      statusCode: 503,
    });

    globalErrorHandler(error, req as never, res as never, next);

    expect(status).toHaveBeenCalledWith(408);
    expect(json).toHaveBeenCalledWith({
      error: "request_timeout",
      message: "Request timed out. Please try again.",
    });
    expect(next).not.toHaveBeenCalled();
  });

  test("returns the established timeout JSON through an actual Express stack", async () => {
    const app = express();
    app.use(requestTimeout(10));
    app.get("/api/v3/nextComment", () => {
      // Deliberately leave the request open so the timeout middleware advances
      // to the error handler registered after the route.
    });
    app.use(globalErrorHandler);

    const response = await request(app).get("/api/v3/nextComment");

    expect(response.status).toBe(408);
    expect(response.body).toEqual({
      error: "request_timeout",
      message: "Request timed out. Please try again.",
    });
  });

  test("keeps the production error middleware after asynchronously installed routes", () => {
    const appSource = fs.readFileSync(
      path.resolve(__dirname, "../../app.ts"),
      "utf8"
    );
    const routeOffset = appSource.indexOf(
      'app.get(\n      "/api/v3/nextComment"'
    );
    const errorHandlerOffset = appSource.indexOf(
      "app.use(globalErrorHandler);"
    );

    expect(routeOffset).toBeGreaterThan(-1);
    expect(errorHandlerOffset).toBeGreaterThan(routeOffset);
  });

  test("preserves an intentional 4xx status and stable Pol.is error code", () => {
    const req = makeRequest();
    const json = jest.fn();
    const status = jest.fn(() => ({ json }));
    const res = {
      statusCode: 400,
      headersSent: false,
      status,
    };
    const next = jest.fn();

    globalErrorHandler(
      new Error(
        "polis_err_param_missing_conversation_id: internal context is not public"
      ),
      req as never,
      res as never,
      next
    );

    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      error: "polis_err_param_missing_conversation_id",
      message: "polis_err_param_missing_conversation_id",
    });
    expect(next).not.toHaveBeenCalled();
  });

  test("preserves a stable Pol.is error code forwarded as a legacy string", () => {
    const req = makeRequest();
    const json = jest.fn();
    const status = jest.fn(() => ({ json }));
    const res = {
      statusCode: 400,
      headersSent: false,
      status,
    };
    const next = jest.fn();

    globalErrorHandler(
      "polis_err_param_parse_failed_conversation_id (val='invalid')",
      req as never,
      res as never,
      next
    );

    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      error: "polis_err_param_parse_failed_conversation_id",
      message: "polis_err_param_parse_failed_conversation_id",
    });
    expect(next).not.toHaveBeenCalled();
  });

  test("does not expose an arbitrary 4xx exception message", () => {
    const req = makeRequest();
    const json = jest.fn();
    const status = jest.fn(() => ({ json }));
    const res = {
      statusCode: 400,
      headersSent: false,
      status,
    };

    globalErrorHandler(
      new Error("sensitive implementation detail"),
      req as never,
      res as never,
      jest.fn()
    );

    expect(json).toHaveBeenCalledWith({
      error: "request_error",
      message: "The request could not be processed. Please try again.",
    });
  });
});
