/**
 * Server entry point
 * This file is responsible for starting the server after the app is configured
 */
import { assertOrdinaryHttpEntrypoint } from "./src/auth/fncp-bootstrap-startup";
// This must precede the app import: this ordinary entrypoint is not TLS-enabled.
assertOrdinaryHttpEntrypoint(process.env);
import { assertFncpProductionAdmission } from "./src/auth/fncp-production-admission";
// Dedicated admission must also precede application imports. Loading the app
// initializes database clients, logging and optional external integrations.
// The admission module and its configuration parsers perform no I/O.
assertFncpProductionAdmission();
import app, { appReady } from "./app";
import Config from "./src/config";
import logger from "./src/utils/logger";
import type { Server } from "node:http";

if (Config.nodeEnv === "production" && Config.enableTelemetry) {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-var-requires
  const tracer = require("dd-trace").init();
}

/**
 * Start the server on the configured port or a provided port
 * @param {number} [port=Config.serverPort] - The port to listen on
 * @returns {Object} The server instance
 */
function startServer(port = Config.serverPort): Server | Promise<Server> {
  assertOrdinaryHttpEntrypoint(process.env);
  // Admission must complete before this process opens a listening socket.
  // Ordinary upstream Pol.is remains unchanged while the dedicated release
  // mode variable is absent.
  const admission = assertFncpProductionAdmission();
  if (admission.dedicated) return startDedicatedServer(port);
  const server = app.listen(port);
  logger.info(`Server started on port ${port}`);
  return server;
}

async function startDedicatedServer(port: number): Promise<Server> {
  // Registration readiness is distinct from a socket or database readiness.
  // No dedicated listener opens until all three have succeeded.
  const runtime = await import("./src/auth/fncp-production-runtime");
  let server: Server | undefined;
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    const deadline = setTimeout(() => process.exit(1), 10000);
    deadline.unref();
    try {
      if (server) await new Promise<void>((resolve, reject) => {
        server!.close(error => error ? reject(error) : resolve());
        server!.closeIdleConnections();
      });
      await runtime.closeFncpProductionRuntime();
    } finally { clearTimeout(deadline); }
  })();
  try {
    await appReady;
    assertFncpProductionAdmission();
    await runtime.prepareFncpProductionRuntime(process.env);
    server = await new Promise<Server>((resolve, reject) => {
      const listener = app.listen(port, () => {
        listener.removeListener("error", reject);
        resolve(listener);
      });
      listener.once("error", reject);
    });
    const stop = () => { void close().catch(() => { process.exitCode = 1; }); };
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    logger.info("FNCP dedicated server ready");
    return server;
  } catch {
    await close();
    throw new Error("FNCP_PRODUCTION_STARTUP_FAILED");
  }
}

const serverStartup = startServer();
if (serverStartup instanceof Promise) {
  void serverStartup.catch(() => {
    logger.error("FNCP_PRODUCTION_STARTUP_FAILED");
    process.exitCode = 1;
  });
}

export { startServer, serverStartup };
export default app;
