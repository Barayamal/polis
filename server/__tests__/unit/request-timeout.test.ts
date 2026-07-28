import { EventEmitter } from "node:events";

import { afterEach, describe, expect, jest, test } from "@jest/globals";

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
});
