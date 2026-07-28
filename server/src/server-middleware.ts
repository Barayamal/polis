import _ from "underscore";
import responseTime from "response-time";

import { addInRamMetric } from "./utils/metered";
import Config from "./config";
import logger from "./utils/logger";
import type { ExpressRequest, ExpressResponse } from "./d";

const devMode = Config.isDevMode;

type TimeoutRequest = ExpressRequest & {
  timedout?: boolean;
  clearTimeout?: () => void;
  emit: (eventName: string, ...args: unknown[]) => boolean;
};

type TimeoutResponse = ExpressResponse & {
  headersSent?: boolean;
  writableEnded?: boolean;
  once: (eventName: string, listener: () => void) => unknown;
  removeListener: (eventName: string, listener: () => void) => unknown;
};

type TimeoutError = Error & {
  code: "ETIMEDOUT";
  timeout: number;
  status: 503;
  statusCode: 503;
};

/**
 * Bound a request without retaining the vulnerable direct connect-timeout
 * dependency. This intentionally preserves the subset of connect-timeout's
 * contract used by Pol.is:
 * - req.timedout starts false and becomes true after the configured delay;
 * - a request "timeout" event is emitted with that delay;
 * - next receives an ETIMEDOUT error, which globalErrorHandler maps to 408;
 * - req.clearTimeout remains available; and
 * - the timer is cancelled when response headers are sent or the response
 *   finishes/closes.
 */
function requestTimeout(delayMs: number) {
  if (!Number.isFinite(delayMs) || delayMs <= 0) {
    throw new TypeError("requestTimeout delay must be a positive number");
  }

  return function (
    req: TimeoutRequest,
    res: TimeoutResponse,
    next: (error?: TimeoutError) => void
  ) {
    let active = true;

    const clear = () => {
      if (!active) return;
      active = false;
      clearTimeout(timer);
      res.removeListener("finish", clear);
      res.removeListener("close", clear);
    };

    const timer = setTimeout(() => {
      // connect-timeout clears its timer as soon as headers are written.
      // Checking here as well avoids a late timeout if a non-standard response
      // implementation does not emit finish/close promptly.
      if (res.headersSent || res.writableEnded) {
        clear();
        return;
      }

      clear();
      req.timedout = true;
      req.emit("timeout", delayMs);

      const error = new Error("Response timeout") as TimeoutError;
      error.code = "ETIMEDOUT";
      error.timeout = delayMs;
      error.status = 503;
      error.statusCode = 503;
      next(error);
    }, delayMs);

    req.clearTimeout = clear;
    req.timedout = false;
    res.once("finish", clear);
    res.once("close", clear);
    next();
  };
}

function middleware_log_request_body(
  req: ExpressRequest,
  res: ExpressResponse,
  next: () => void
) {
  if (devMode) {
    // Skip logging if path includes 'pca2'
    if (req.path.includes("pca2")) {
      return next();
    }

    let b = "";
    if (req.body) {
      const temp = _.clone(req.body);
      if (temp.password) {
        temp.password = "some_password";
      }
      if (temp.newPassword) {
        temp.newPassword = "some_password";
      }
      if (temp.password2) {
        temp.password2 = "some_password";
      }
      if (temp.hname) {
        temp.hname = "somebody";
      }
      if (temp.polisApiKey) {
        temp.polisApiKey = "pkey_somePolisApiKey";
      }
      b = JSON.stringify(temp);
    }
    logger.debug("middleware_log_request_body", { path: req.path, body: b });
  } else {
    // don't log the route or params, since Heroku does that for us.
  }
  next();
}

// HTTP access log middleware (prod only)
function middleware_http_json_logger(
  req: ExpressRequest,
  res: ExpressResponse,
  next: () => void
) {
  if (devMode) {
    return next();
  }

  const startNs = process.hrtime.bigint();

  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - startNs) / 1e6;
    const statusCode = res.statusCode;

    const log: Record<string, unknown> = {
      message: "http_request",
      service: "server",
      env: Config.ddEnv || "prod",
      http: {
        method: req.method,
        url: req.originalUrl,
        route: (req as unknown as { route?: { path?: string } }).route?.path,
        status_code: statusCode,
      },
      network: { client: { ip: req.ip } },
      useragent: (req.headers as Record<string, string | string[] | undefined>)[
        "user-agent"
      ],
      duration_ms: durationMs,
    };

    // status level
    let level: "error" | "warn" | "info";
    if (statusCode >= 500) level = "error";
    else if (statusCode >= 400) level = "warn";
    else level = "info";

    logger.log(level, "http_request", log);
  });

  next();
}

function middleware_log_middleware_errors(
  err: any,
  req: ExpressRequest,
  res: ExpressResponse,
  next: (arg0?: any) => void
) {
  if (!err) {
    return next();
  }
  logger.error("middleware_log_middleware_errors", err);
  next(err);
}

function middleware_check_if_options(
  req: { method: string },
  res: { send: (arg0: number) => any },
  next: () => any
) {
  if (req.method.toLowerCase() !== "options") {
    return next();
  }
  return res.send(204);
}

const middleware_responseTime_start = responseTime(function (
  req: { route: { path: any } },
  res: any,
  time: number
) {
  if (req && req.route && req.route.path) {
    const path = req.route.path;
    time = Math.trunc(time);
    addInRamMetric(path, time);
  }
});

// Global error handler to prevent crashes from database constraint violations
// This is a safety net for errors that might not be caught in route handlers
function globalErrorHandler(
  err: any,
  req: ExpressRequest,
  res: ExpressResponse,
  next: (e?: any) => void
) {
  //structured error log
  const status = res.statusCode >= 400 ? res.statusCode : 500;
  logger.error("request_error", {
    status: status >= 500 ? "error" : "warn",
    service: "server",
    env: Config.ddEnv || "prod",
    http: {
      method: req.method,
      url: req.originalUrl,
      status_code: status,
    },
    error: { kind: err.name, stack: err.stack, message: err.message },
    code: err.code,
    constraint: err.constraint,
    oidcSub: (req as any).jwtPayload?.sub || (req as any).p?.oidcSub,
  });

  // Handle database constraint violations specifically
  if (err.code === "23505") {
    if (err.constraint === "oidc_user_mappings_pkey") {
      logger.warn("Global handler: OIDC mapping constraint violation", {
        constraint: err.constraint,
        url: req.originalUrl,
        oidcSub: req.jwtPayload?.sub,
      });

      return res.status(429).json({
        error: "authentication_conflict",
        message:
          "Authentication system encountered a temporary conflict. Please try again.",
        retry_after: 1,
      });
    } else {
      logger.warn("Global handler: Database constraint violation", {
        constraint: err.constraint,
        url: req.originalUrl,
      });

      return res.status(409).json({
        error: "database_constraint_violation",
        message:
          "The requested operation conflicts with existing data. Please try again.",
      });
    }
  }

  // Handle JWT errors
  if (err.name === "UnauthorizedError") {
    return res.status(401).json({
      error: "unauthorized",
      message: "Authentication required or invalid token",
    });
  }

  // Handle Express timeout errors
  if (err.code === "ETIMEDOUT" || err.timeout) {
    return res.status(408).json({
      error: "request_timeout",
      message: "Request timed out. Please try again.",
    });
  }

  // Handle other database errors
  if (err.code && typeof err.code === "string" && err.code.startsWith("23")) {
    return res.status(400).json({
      error: "database_error",
      message:
        "Database operation failed. Please check your data and try again.",
    });
  }

  // Don't respond if response already sent
  if (res.headersSent) {
    logger.warn(
      "Global error handler: Response already sent, forwarding to default handler"
    );
    return next(err);
  }

  // Legacy parameter and route middleware sets an intentional 4xx status
  // before forwarding a stable polis_err_* code. Preserve that public
  // contract now that this handler is correctly installed after the routes.
  // Do not expose arbitrary exception messages.
  if (status >= 400 && status < 500) {
    // Legacy middleware calls next("polis_err_*") with a string, while newer
    // handlers pass Error instances. Normalise both forms before extracting
    // only the stable public code.
    const errorMessage =
      typeof err === "string"
        ? err
        : typeof err?.message === "string"
          ? err.message
          : "";
    const publicError =
      /^polis_(?:err|fail)_[a-z0-9_]+(?:\b|$)/u.test(errorMessage)
        ? errorMessage.match(/^polis_(?:err|fail)_[a-z0-9_]+/u)?.[0]
        : undefined;

    return res.status(status).json({
      error: publicError || "request_error",
      message:
        publicError || "The request could not be processed. Please try again.",
    });
  }

  // Generic error response for everything else
  return res.status(500).json({
    error: "internal_server_error",
    message: "An unexpected error occurred. Please try again.",
    // Include error details in development mode only
    ...(devMode && {
      details: err.message,
      stack: err.stack,
    }),
  });
}

// Setup global process-level error handlers
function setupGlobalProcessHandlers() {
  // Global uncaught exception handler (last resort)
  process.on("uncaughtException", (err) => {
    logger.error("Uncaught exception:", {
      error: err.message,
      stack: err.stack,
      code: (err as any).code,
      constraint: (err as any).constraint,
    });

    // Don't exit for database constraint violations - they're recoverable
    if ((err as any).code === "23505") {
      logger.warn(
        "Uncaught database constraint violation - not exiting process"
      );
      return;
    }

    // For other critical errors, gracefully shutdown
    logger.error("Critical error occurred, shutting down gracefully...");
    process.exit(1);
  });

  // Global unhandled promise rejection handler
  process.on("unhandledRejection", (reason, _promise) => {
    logger.error("Unhandled promise rejection:", {
      reason: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
      code: (reason as any)?.code,
      constraint: (reason as any)?.constraint,
    });

    // Don't exit for database constraint violations
    if ((reason as any)?.code === "23505") {
      logger.warn(
        "Unhandled promise rejection with constraint violation - not exiting process"
      );
      return;
    }

    // For other promise rejections, log but don't exit immediately
    logger.warn(
      "Unhandled promise rejection occurred - monitoring for stability"
    );
  });
}

export {
  middleware_log_request_body,
  middleware_log_middleware_errors,
  middleware_check_if_options,
  middleware_responseTime_start,
  middleware_http_json_logger,
  requestTimeout,
  globalErrorHandler,
  setupGlobalProcessHandlers,
};
