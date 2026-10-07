import { generateTokenP } from "./generate-token";
import Config from "../config";
import logger from "../utils/logger";
import pg from "../db/pg-query";

function generateAndRegisterZinvite(zid: number, generateShort: any) {
  let len = 10;
  if (generateShort) {
    len = 6;
  }
  return generateTokenP(len, false).then(function (zinvite: string) {
    return pg
      .queryP(
        "INSERT INTO zinvites (zid, zinvite, created, uuid) VALUES ($1, $2, default, gen_random_uuid());",
        [zid, zinvite]
      )
      .then(function (_rows: any) {
        return zinvite;
      });
  });
}

async function createAnonUser(): Promise<number> {
  return new Promise((resolve, reject) => {
    pg.query(
      "INSERT INTO users (created) VALUES (default) RETURNING uid;",
      [],
      function (err: any, results: { rows: { uid: number }[] }) {
        if (err || !results || !results.rows || !results.rows.length) {
          logger.error("polis_err_create_empty_user", err);
          reject(new Error("polis_err_create_empty_user"));
          return;
        }
        resolve(results.rows[0].uid);
      }
    );
  });
}

/**
 * Preserve existing mapping policy using one primary client per transaction.
 * Retry/recovery requires a confirmed rollback, never an uncertain COMMIT.
 */
async function getOrCreateUserIDFromOidcSub(
  oidcSub: string,
  oidcUser: any,
  retryCount = 0
): Promise<number> {
  if (Config.fncpDedicatedProduction) return getOrCreateDedicatedOidcUser(oidcSub, oidcUser);
  const maxRetries = 3;
  let email: string;
  let displayName: string;
  let username: string;
  try {
    const namespace = Config.authNamespace;
    email = oidcUser.email || oidcUser[`${namespace}email`];
    const name = oidcUser.name || oidcUser[`${namespace}name`] || oidcUser.nickname;
    if (!email) {
      if (Config.freshBootstrapLocalOnly) throw new Error("FNCP_FRESH_BOOTSTRAP_OIDC_MAPPING_FAILED");
      throw new Error(`OIDC user missing email. Sub: ${oidcSub}, User: ${JSON.stringify(oidcUser)}`);
    }
    displayName = name || oidcUser.nickname || email.split("@")[0];
    username = oidcUser.nickname || email.split("@")[0];
  } catch (error) {
    if (Config.freshBootstrapLocalOnly) throw new Error("FNCP_FRESH_BOOTSTRAP_OIDC_MAPPING_FAILED");
    throw error;
  }

  try {
    return await pg.withTransaction(async (query) => {
      const mapping = await query("SELECT uid FROM oidc_user_mappings WHERE oidc_sub = $1", [oidcSub]);
      if (mapping.rows.length) return mapping.rows[0].uid;

      const user = await query(`
        INSERT INTO users (email, hname, username, is_owner, created)
        VALUES ($1, $2, $3, $4, now_as_millis())
        ON CONFLICT (email) DO UPDATE SET
          hname = EXCLUDED.hname,
          username = EXCLUDED.username
        RETURNING uid
      `, [email, displayName, username, true]);
      if (!user.rows.length) throw new Error("Failed to create or find user");
      const uid = user.rows[0].uid;
      const existing = await query("SELECT oidc_sub FROM oidc_user_mappings WHERE uid = $1", [uid]);
      if (existing.rows.length) {
        const existingOidcSub = existing.rows[0].oidc_sub;
        if (existingOidcSub === oidcSub) return uid;
        // Preserve ordinary mapping policy; this is not an eligibility decision.
        if (!Config.freshBootstrapLocalOnly) logger.warn(
          `Local user ${uid} (${email}) was mapped to old OIDC sub ${existingOidcSub}. Overwriting with new mapping for ${oidcSub}.`
        );
        await query("DELETE FROM oidc_user_mappings WHERE oidc_sub = $1 OR uid = $2", [oidcSub, uid]);
        await query("INSERT INTO oidc_user_mappings (oidc_sub, uid, created) VALUES ($1, $2, now_as_millis())", [oidcSub, uid]);
      } else {
        await query("INSERT INTO oidc_user_mappings (oidc_sub, uid, created) VALUES ($1, $2, now_as_millis()) ON CONFLICT (oidc_sub) DO NOTHING", [oidcSub, uid]);
      }
      return uid;
    });
  } catch (error: any) {
    if (Config.freshBootstrapLocalOnly) {
      logger.error("fncp_fresh_bootstrap_oidc_mapping_failed");
      throw new Error("FNCP_FRESH_BOOTSTRAP_OIDC_MAPPING_FAILED");
    }
    logger.error(`Failed to get or create user for OIDC sub ${oidcSub}:`, error);
    if (!pg.transactionRolledBack(error) || error.code !== "23505") throw error;

    if (error.constraint === "oidc_user_mappings_pkey") {
      if (retryCount < maxRetries) {
        const retryDelay = 100 + Math.random() * 200;
        logger.warn(`OIDC mapping constraint violation (attempt ${retryCount + 1}/${maxRetries + 1}), retrying after ${retryDelay}ms for sub: ${oidcSub}`);
        await new Promise((resolve) => setTimeout(resolve, retryDelay));
        return getOrCreateUserIDFromOidcSub(oidcSub, oidcUser, retryCount + 1);
      }
      try {
        const rows = await pg.queryP_readOnly("SELECT uid FROM oidc_user_mappings WHERE oidc_sub = $1", [oidcSub]) as { uid: number }[];
        if (!rows.length) throw new Error(`OIDC mapping not found after retries for sub: ${oidcSub}`);
        return rows[0].uid;
      } catch (lookupError) {
        logger.error(`Final lookup failed for OIDC sub ${oidcSub}:`, lookupError);
        throw new Error(`Unable to create or find user mapping for OIDC sub: ${oidcSub}. This may be due to high concurrency. Please try again.`);
      }
    }

    if (error.constraint === "users_email_key" || error.constraint === "oidc_user_mappings_uid_key") {
      logger.warn(`Constraint violation detected for ${email}, attempting recovery...`);
      try {
        // Recovery may insert a mapping: keep reads and insert on one primary
        // transaction, rather than mixing a read replica with independent writes.
        return await pg.withTransaction(async (query) => {
          const users = await query("SELECT uid FROM users WHERE LOWER(email) = LOWER($1)", [email]);
          if (!users.rows.length) throw new Error(`User with email ${email} not found during recovery`);
          const uid = users.rows[0].uid;
          const mapping = await query("SELECT oidc_sub FROM oidc_user_mappings WHERE uid = $1", [uid]);
          if (!mapping.rows.length) {
            await query("INSERT INTO oidc_user_mappings (oidc_sub, uid, created) VALUES ($1, $2, now_as_millis()) ON CONFLICT (oidc_sub) DO NOTHING", [oidcSub, uid]);
          }
          return uid;
        });
      } catch (recoveryError) {
        logger.error("Recovery attempt failed:", recoveryError);
        throw new Error(`Unable to create or find user for email: ${email}. Original error: ${error.message}, Recovery error: ${recoveryError}`);
      }
    }
    throw error;
  }
}

/** A verified subject is the identity. Email equality never authorizes replacing
 * another subject's mapping in the dedicated pilot. Preserve upstream policy
 * outside this dedicated mode and never include identity claims in diagnostics.
 */
async function getOrCreateDedicatedOidcUser(subject: string, claims: any): Promise<number> {
  const failure = () => new Error("FNCP_PRODUCTION_OIDC_MAPPING_FAILED");
  try {
    const namespace = Config.authNamespace || "";
    const email = claims?.email ?? claims?.[`${namespace}email`];
    const verified = claims?.email_verified ?? claims?.[`${namespace}email_verified`];
    if (typeof subject !== "string" || !subject || subject.length > 512 || /[\u0000-\u0020\u007f]/u.test(subject) ||
        typeof email !== "string" || email.length > 256 || !/^[^\s@]+@[^\s@]+$/u.test(email) || verified !== true) throw failure();
    const name = claims?.name ?? claims?.[`${namespace}name`] ?? claims?.nickname ?? email.split("@")[0];
    if (typeof name !== "string" || name.length > 746) throw failure();
    return await pg.withTransaction(async query => {
      const mapped = await query("SELECT uid FROM oidc_user_mappings WHERE oidc_sub = $1 FOR UPDATE", [subject]);
      if (mapped.rows.length === 1 && Number.isSafeInteger(mapped.rows[0].uid)) return mapped.rows[0].uid;
      const created = await query(`INSERT INTO users (email, hname, username, is_owner, created)
        VALUES ($1, $2, $3, false, now_as_millis()) ON CONFLICT (email) DO NOTHING RETURNING uid`,
        [email, name, email.split("@")[0].slice(0, 128)]);
      if (created.rows.length !== 1 || !Number.isSafeInteger(created.rows[0].uid)) throw failure();
      const uid = created.rows[0].uid;
      await query("INSERT INTO oidc_user_mappings (oidc_sub, uid, created) VALUES ($1, $2, now_as_millis())", [subject, uid]);
      return uid;
    });
  } catch (error: any) {
    // A competing creation may have committed the exact subject first. Recover
    // only after confirmed rollback and only by that subject on the primary.
    if (pg.transactionRolledBack(error) && error?.code === "23505" && error?.constraint === "oidc_user_mappings_pkey") {
      try {
        const rows = await pg.queryP("SELECT uid FROM oidc_user_mappings WHERE oidc_sub = $1", [subject]) as { uid: number }[];
        if (rows.length === 1 && Number.isSafeInteger(rows[0].uid)) return rows[0].uid;
      } catch { /* Preserve the sanitized failure below. */ }
    }
    logger.error("fncp_production_oidc_mapping_failed");
    throw failure();
  }
}

export { createAnonUser, generateAndRegisterZinvite, getOrCreateUserIDFromOidcSub };
