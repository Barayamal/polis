import { createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import pg from "../db/pg-query";
import { getPrivateKey, getPublicKey } from "./jwt-utils";
import { assertFncpProductionDatabaseReady } from "./fncp-production-database";

export async function prepareFncpProductionRuntime(env: NodeJS.ProcessEnv): Promise<void> {
  try {
    const privateKey = createPrivateKey(getPrivateKey());
    const publicKey = createPublicKey(getPublicKey());
    if (privateKey.asymmetricKeyType !== "rsa" || publicKey.asymmetricKeyType !== "rsa" ||
        (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw Error();
    const expected = createPublicKey(privateKey).export({ type: "spki", format: "der" });
    const supplied = publicKey.export({ type: "spki", format: "der" });
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw Error();
  } catch { throw new Error("FNCP_PRODUCTION_SIGNING_KEYS_NOT_READY"); }
  await assertFncpProductionDatabaseReady((sql, params) => pg.queryP(sql, params), env);
}

export const closeFncpProductionRuntime = () => pg.close();
