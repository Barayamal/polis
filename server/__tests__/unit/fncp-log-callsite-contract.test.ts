import fs from "node:fs";
import path from "node:path";

import { describe, expect, test } from "@jest/globals";

const serverRoot = path.resolve(__dirname, "../..");

function source(relativePath: string): string {
  return fs.readFileSync(path.join(serverRoot, relativePath), "utf8");
}

describe("FNCP logging call-site contract", () => {
  test("installs the sensitive boundary before Morgan and skips FNCP dev access logs", () => {
    const app = source("app.ts");
    const boundaryIndex = app.indexOf("app.use(fncpLogBoundaryMiddleware)");
    const morganIndex = app.indexOf('morgan("dev"');

    expect(boundaryIndex).toBeGreaterThan(-1);
    expect(morganIndex).toBeGreaterThan(boundaryIndex);
    expect(app).toContain(
      "skip: (req: express.Request) => isFncpSensitiveRequest(req)"
    );
  });

  test("omits FNCP request bodies and error objects before calling the logger", () => {
    const middleware = source("src/server-middleware.ts");

    expect(middleware).toMatch(
      /if \(isFncpSensitiveRequest\(req\)\) \{\s+logger\.debug\("fncp_request_body_omitted"\);\s+return next\(\);/u
    );
    expect(middleware).toMatch(
      /if \(isFncpSensitiveRequest\(req\)\) \{\s+logger\.error\("fncp_middleware_error"\);/u
    );
    expect(middleware).toContain(
      "const isFncpRequest = isFncpSensitiveRequest(req);"
    );
    expect(middleware).toContain(
      "url: isFncpRequest ? req.path : req.originalUrl"
    );
  });

  test("never serializes participationInit req.p or resolution errors for FNCP", () => {
    const participation = source("src/routes/participation.ts");

    expect(participation).toMatch(
      /if \(isFncpSensitiveRequest\(req\)\) \{\s+logger\.debug\("handle_GET_participationInit_fncp"\);\s+\} else \{\s+logger\.debug\(`handle_GET_participationInit \$\{JSON\.stringify\(req\.p\)\}`\);/u
    );
    expect(participation).toMatch(
      /if \(isFncpSensitiveRequest\(req\)\) \{\s+logger\.debug\("FNCP participant user resolution failed"\);\s+\} else \{/u
    );
    expect(participation).toMatch(
      /if \(isFncpSensitiveRequest\(req\)\) \{\s+logger\.error\("FNCP participationInit failed"\);\s+\} else \{/u
    );
  });

  test("records the intentional POST diagnostic suppression trade-off", () => {
    const documentation = source("docs/FNCP_LOGGING_BOUNDARY.md");

    expect(documentation).toMatch(
      /suppresses\s+request diagnostics for \*\*every\*\* `POST`/u
    );
    expect(documentation).toContain("/api/v3/comments");
    expect(documentation).toContain("/api/v3/votes");
    expect(documentation).toContain("/api/v3/joinWithInvite");
    expect(documentation).toContain(
      "Ordinary upstream behaviour is unchanged when enforcement is off."
    );
  });
});
