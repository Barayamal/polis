#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import {
  readFile,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CONVERSATION_ID = /^[0-9][0-9A-Za-z]{5,99}$/u;
const BOOTSTRAP_ID = /^9fncpBootstrap[0-9a-f]{48}$/u;

function exactValue(source, name) {
  const expression = new RegExp(`^${name}=([^\\r\\n]*)$`, "gmu");
  const matches = [...source.matchAll(expression)];
  if (matches.length !== 1) {
    throw new Error("invalid bootstrap environment");
  }
  return matches[0][1];
}

function replaceExactValue(source, name, value) {
  const expression = new RegExp(`^${name}=[^\\r\\n]*$`, "gmu");
  if ([...source.matchAll(expression)].length !== 1) {
    throw new Error("invalid bootstrap environment");
  }
  return source.replace(expression, `${name}=${value}`);
}

/**
 * Replace both conversation bindings and the completion marker through one
 * same-directory rename. No identifier or environment value is emitted.
 */
export async function rewriteSyntheticBootstrapBinding(
  environmentPath,
  conversationResponsePath
) {
  const [environment, rawResponse] = await Promise.all([
    readFile(environmentPath, "utf8"),
    readFile(conversationResponsePath, "utf8"),
  ]);
  const response = JSON.parse(rawResponse);
  const createdId =
    response &&
    !Array.isArray(response) &&
    typeof response === "object" &&
    typeof response.conversation_id === "string"
      ? response.conversation_id
      : "";
  const gatewayId = exactValue(
    environment,
    "FNCP_GATEWAY_CONVERSATION_ID"
  );
  const providerId = exactValue(
    environment,
    "FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID"
  );
  if (
    exactValue(environment, "FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE") !==
      "false" ||
    gatewayId !== providerId ||
    !BOOTSTRAP_ID.test(gatewayId) ||
    !CONVERSATION_ID.test(createdId) ||
    BOOTSTRAP_ID.test(createdId) ||
    createdId === gatewayId
  ) {
    throw new Error("invalid synthetic bootstrap transition");
  }

  let updated = replaceExactValue(
    environment,
    "FNCP_GATEWAY_CONVERSATION_ID",
    createdId
  );
  updated = replaceExactValue(
    updated,
    "FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID",
    createdId
  );
  updated = replaceExactValue(
    updated,
    "FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE",
    "true"
  );
  if (
    exactValue(updated, "FNCP_GATEWAY_CONVERSATION_ID") !== createdId ||
    exactValue(updated, "FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID") !==
      createdId ||
    exactValue(updated, "FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE") !== "true"
  ) {
    throw new Error("incomplete synthetic bootstrap transition");
  }

  const temporaryPath = resolve(
    dirname(environmentPath),
    `.${basename(environmentPath)}.next-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  try {
    await writeFile(temporaryPath, updated, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporaryPath, environmentPath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

const invokedPath = process.argv[1]
  ? resolve(process.argv[1])
  : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) {
    process.stderr.write("Synthetic bootstrap binding update refused.\n");
    process.exitCode = 1;
  } else {
    rewriteSyntheticBootstrapBinding(process.argv[2], process.argv[3]).catch(
      () => {
        process.stderr.write("Synthetic bootstrap binding update refused.\n");
        process.exitCode = 1;
      }
    );
  }
}
