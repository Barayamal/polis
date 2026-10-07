/** Fixed executable for an independently owned fresh child process only.
 * Parent must generate/attest the fresh profile and IPC public trust, relay
 * original issuer cancellation, bound/observe child exit, and own DB/container
 * cleanup. No shell, path-selected app, retained .env, plaintext or web-admin
 * fallback. No app is imported until private IPC/profile/trust validation.
 */
import { fstatSync, statSync } from "node:fs";
import { freshBootstrapStartup } from "../auth/fncp-bootstrap-startup";
import { createBootstrapHttpsRuntime } from "./https-runtime";

export function assertBootstrapChild() {
  if (
    process.argv.length !== 2 ||
    process.execArgv.length !== 0 ||
    !process.connected ||
    typeof process.send !== "function"
  )
    throw new Error("FNCP_FRESH_BOOTSTRAP_CHILD_REQUIRED");
  // Parent must discard stdout/stderr at the OS descriptor boundary. This
  // includes legacy process-global diagnostics before request log suppression.
  const target = statSync("/dev/null");
  for (const fd of [0, 1, 2]) {
    const actual = fstatSync(fd);
    if (
      !actual.isCharacterDevice() ||
      actual.dev !== target.dev ||
      actual.ino !== target.ino ||
      actual.rdev !== target.rdev
    )
      throw new Error("FNCP_FRESH_BOOTSTRAP_PRIVATE_STDIO_REQUIRED");
  }
  // eslint-disable-next-line no-restricted-properties -- Validate the attested child environment before importing Config or app.
  if (!freshBootstrapStartup(process.env))
    throw new Error("FNCP_FRESH_BOOTSTRAP_PROFILE_REQUIRED");
}

export function runBootstrapChild() {
  assertBootstrapChild();
  let attempted = false,
    stopping = false;
  let runtime: Awaited<ReturnType<typeof createBootstrapHttpsRuntime>>;
  const aborter = new AbortController();
  const exit = (code: number) => {
    if (stopping) return;
    stopping = true;
    aborter.abort();
    // Exit terminates this dedicated child's pools/timers, not its independent
    // database or Docker resources. Parent must observe actual process exit.
    const fallback = setTimeout(() => process.exit(code || 1), 2200);
    void Promise.resolve(runtime?.close()).then(
      () => {
        clearTimeout(fallback);
        if (process.connected)
          process.send(
            {
              type: "closed",
              listenerVerified: !!runtime?.summary().listenerClosureVerified,
            },
            undefined,
            {},
            () => process.exit(code)
          );
        else process.exit(code);
        setTimeout(() => process.exit(code || 1), 100).unref();
      },
      () => process.exit(1)
    );
  };
  process.once("disconnect", () => exit(1));
  process.once("SIGTERM", () => exit(1));
  process.once("SIGINT", () => exit(1));
  process.once("uncaughtException", () => exit(1));
  process.once("unhandledRejection", () => exit(1));
  const receiveDeadline = setTimeout(() => exit(1), 2000);
  const maximumLifetime = setTimeout(() => exit(1), 120000);
  maximumLifetime.unref();
  process.on("message", (message) => {
    if (
      message &&
      typeof message === "object" &&
      Object.keys(message).length === 1 &&
      message["type"] === "stop"
    )
      return exit(0);
    if (attempted || stopping) return exit(1);
    attempted = true;
    clearTimeout(receiveDeadline);
    void (async () => {
      if (
        !message ||
        typeof message !== "object" ||
        Array.isArray(message) ||
        Object.keys(message).sort().join() !==
          "issuer,publicJwk,seedStatementsJson,type" ||
        message["type"] !== "start" ||
        // eslint-disable-next-line no-restricted-properties -- Compare IPC trust to the validated child environment without importing Config.
        message["issuer"] !== process.env.AUTH_ISSUER
      )
        throw new Error("invalid");
      runtime = await createBootstrapHttpsRuntime({
        trust: {
          issuer: message["issuer"],
          publicJwk: message["publicJwk"],
          seedStatementsJson: message["seedStatementsJson"],
        },
        signal: aborter.signal,
        initialize: async () => {
          // CommonJS path is fixed in the compiled server/dist tree. The normal
          // index.js is never imported: it deliberately rejects this profile.
          const application = require("../../app");
          return { handler: application.default, ready: application.appReady };
        },
      });
      if (stopping || !process.connected) {
        await runtime.close();
        return;
      }
      process.send(
        { type: "HOST_HTTPS_APP_ROUTES_READY", ...runtime.configuration() },
        undefined,
        {},
        (error) => {
          if (error) exit(1);
        }
      );
      const watch = setInterval(() => {
        if (runtime.summary().closed) {
          clearInterval(watch);
          exit(1);
        }
      }, 25);
      watch.unref();
    })().catch(() => exit(1));
  });
}

if (require.main === module) {
  try {
    runBootstrapChild();
  } catch {
    process.exit(1);
  }
}
