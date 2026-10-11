import type { Request, Response, NextFunction } from "express";

/** The dedicated image serves only the reviewed participant/provider contract.
 * Native upstream report identifiers and private mappings are not staff
 * authorization. A separate authenticated staff export service is required.
 * Ordinary upstream and existing synthetic entrypoints keep their own routes.
 */
const ROUTES = new Set([
  "GET /api/v3/comments",
  "GET /api/v3/math/pca2",
  "GET /api/v3/nextComment",
  "GET /api/v3/participationInit",
  "POST /api/v3/votes",
  "POST /fncp/private/xid-allowlist/upsert",
  "POST /fncp/private/xid-allowlist/readback",
  "POST /fncp/private/xid-allowlist/remove",
]);

// eslint-disable-next-line no-restricted-properties -- Keep this pure route guard independent of Config's import side effects.
export function createFncpProductionRouteBoundary(env: NodeJS.ProcessEnv = process.env) {
  const dedicated = env.FNCP_OPTION_C_RELEASE_MODE === "production";
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!dedicated || ROUTES.has(`${req.method} ${req.path}`)) {
      next();
      return;
    }
    res.status(404).json({ error: "Not found." });
  };
}
