import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test } from "@jest/globals";

const packageJson = JSON.parse(
  readFileSync(resolve(__dirname, "../../package.json"), "utf8")
) as {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};
const packageLock = JSON.parse(
  readFileSync(resolve(__dirname, "../../package-lock.json"), "utf8")
) as {
  packages: Record<string, { version?: string }>;
};
const appSource = readFileSync(resolve(__dirname, "../../app.ts"), "utf8");
const fileFetcherSource = readFileSync(
  resolve(__dirname, "../../src/utils/file-fetcher.ts"),
  "utf8"
);
const moderationSource = readFileSync(
  resolve(__dirname, "../../src/utils/moderation.ts"),
  "utf8"
);
const serverMiddlewareSource = readFileSync(
  resolve(__dirname, "../../src/server-middleware.ts"),
  "utf8"
);
const httpMiddlewareSource = readFileSync(
  resolve(__dirname, "../../src/http-middleware.ts"),
  "utf8"
);
const sqlTablesSource = readFileSync(
  resolve(__dirname, "../../src/db/sql.ts"),
  "utf8"
);
const localQueryBuilderSource = readFileSync(
  resolve(__dirname, "../../src/db/postgres-query-builder.ts"),
  "utf8"
);
const parameterizedQueryConsumers = [
  { path: "src/comment.ts", expectedExecutions: 1 },
  { path: "src/participant.ts", expectedExecutions: 1 },
  { path: "src/routes/conversations.ts", expectedExecutions: 3 },
  { path: "src/routes/implicitConversation.ts", expectedExecutions: 1 },
  { path: "src/routes/metadata.ts", expectedExecutions: 1 },
  { path: "src/routes/participation.ts", expectedExecutions: 1 },
  { path: "src/routes/reports.ts", expectedExecutions: 1 },
  { path: "src/routes/users.ts", expectedExecutions: 1 },
  { path: "src/routes/votes.ts", expectedExecutions: 1 },
].map(({ path, expectedExecutions }) => ({
  path,
  expectedExecutions,
  source: readFileSync(resolve(__dirname, `../../${path}`), "utf8"),
}));

describe("minimal FNCP production dependency contract", () => {
  test("test and development HTTP clients stay outside production dependencies", () => {
    expect(packageJson.dependencies).not.toHaveProperty("axios");
    expect(packageJson.dependencies).not.toHaveProperty("morgan");
    expect(packageJson.devDependencies.axios).toBe("1.18.1");
    expect(packageJson.devDependencies.morgan).toBe("1.11.0");
    expect(appSource).not.toMatch(/import\s+morgan\s+from\s+"morgan"/);
    expect(appSource).toContain('const morgan = require("morgan")');
  });

  test("unused mail and CLI packages are absent", () => {
    for (const unused of [
      "nodemailer",
      "nodemailer-mailgun-transport",
      "optimist",
    ]) {
      expect(packageJson.dependencies).not.toHaveProperty(unused);
      expect(packageJson.devDependencies).not.toHaveProperty(unused);
    }
  });

  test("the legacy node-sql and monolithic Lodash runtime are absent", () => {
    for (const dependency of ["sql", "lodash"]) {
      expect(packageJson.dependencies).not.toHaveProperty(dependency);
      expect(packageJson.devDependencies).not.toHaveProperty(dependency);
    }
    expect(packageLock.packages).not.toHaveProperty("node_modules/sql");
    expect(packageLock.packages).not.toHaveProperty("node_modules/lodash");
    expect(packageLock.packages).not.toHaveProperty(
      "node_modules/sql/node_modules/lodash"
    );
    expect(sqlTablesSource).toContain(
      'import sql from "./postgres-query-builder"'
    );
    expect(sqlTablesSource).not.toMatch(/from\s+["']sql["']/u);
    expect(localQueryBuilderSource).toContain(
      "function quoteIdentifier(identifier: string)"
    );
    expect(localQueryBuilderSource).toContain("resolveWriteValues");
  });

  test.each(parameterizedQueryConsumers)(
    "$path forwards every local-builder text/value pair",
    ({ source, expectedExecutions }) => {
      expect(source.match(/\.toQuery\(\)/gu)).toHaveLength(expectedExecutions);
      expect(source).not.toContain(".toString()");
      expect(
        source.match(
          /(?:queryP_readOnly|queryP|query_readOnly|query)\(\s*([A-Za-z_$][\w$]*)\.text,\s*\1\.values/gu
        )
      ).toHaveLength(expectedExecutions);
    }
  );

  test("builder-backed report timestamps preserve database time without string replacement", () => {
    const reportSource = parameterizedQueryConsumers.find(
      ({ path }) => path === "src/routes/reports.ts"
    )?.source;
    expect(reportSource).toContain("modified: databaseNowAsMillis()");
    expect(localQueryBuilderSource).toContain(
      'const DATABASE_NOW_AS_MILLIS = new TrustedSqlValue("now_as_millis()")'
    );
    expect(reportSource).not.toContain(".replace(");
  });

  test("bounded compatible production upgrades are pinned", () => {
    expect(packageJson.dependencies["dd-trace"]).toBe("5.118.0");
    expect(packageJson.dependencies.underscore).toBe("1.13.8");
  });

  test("deprecated request clients are absent from the server runtime", () => {
    for (const dependency of ["request", "request-promise", "simple-oauth2"]) {
      expect(packageJson.dependencies).not.toHaveProperty(dependency);
    }
    expect(packageJson.devDependencies).not.toHaveProperty(
      "@types/request-promise"
    );
    expect(fileFetcherSource).not.toMatch(
      /from\s+["']request(?:-promise)?["']|require\(["']request/u
    );
    expect(moderationSource).not.toMatch(
      /from\s+["']request(?:-promise)?["']|require\(["']request/u
    );
    expect(fileFetcherSource).toContain('redirect: "follow"');
    expect(moderationSource).toContain(
      "AbortSignal.timeout(IP_LOOKUP_TIMEOUT_MS)"
    );
  });

  test("supported Express middleware replaces the legacy Connect stack", () => {
    for (const dependency of ["body-parser", "connect-timeout"]) {
      expect(packageJson.dependencies).not.toHaveProperty(dependency);
    }
    expect(packageJson.devDependencies).not.toHaveProperty(
      "@types/connect-timeout"
    );

    // Express only supports the latest release in each maintained major line.
    // Pin the reviewed 4.x release rather than silently drifting the framework.
    expect(packageJson.dependencies.express).toBe("4.22.2");
    expect(packageJson.dependencies.compression).toBe("1.8.1");
    expect(packageJson.dependencies["cookie-parser"]).toBe("1.4.7");
    expect(packageJson.devDependencies["@types/compression"]).toBe("1.8.1");
    expect(packageJson.devDependencies["@types/cookie-parser"]).toBe("1.4.10");
    expect(packageLock.packages["node_modules/express"]?.version).toBe(
      "4.22.2"
    );
    expect(packageLock.packages).not.toHaveProperty("node_modules/connect");
    expect(packageLock.packages).not.toHaveProperty("node_modules/multiparty");

    // Preserve the existing body limit, JSON suffix support, nested form
    // semantics, cookies, compression, proxy handling and FNCP fail-closed
    // middleware order.
    expect(appSource).toContain('app.set("trust proxy", 1)');
    expect(httpMiddlewareSource).toContain("express.json({");
    expect(httpMiddlewareSource).toContain(
      'type: ["application/json", "application/*+json"]'
    );
    expect(httpMiddlewareSource).toContain('const REQUEST_BODY_LIMIT = "50mb"');
    expect(httpMiddlewareSource).toContain("extended: true");
    expect(httpMiddlewareSource).toContain("cookieParser()");
    expect(httpMiddlewareSource).toContain("compression()");
    expect(httpMiddlewareSource).toContain('req.is("multipart/form-data")');
    expect(appSource).not.toMatch(
      /express\.(?:bodyParser|cookieParser|compress)/u
    );
    expect(appSource).toMatch(
      /app\.use\(rejectUnsupportedMultipart\);[\s\S]*app\.use\(createJsonBodyParser\(\)\);[\s\S]*app\.use\(createUrlencodedBodyParser\(\)\);[\s\S]*app\.use\(createCookieParser\(\)\);[\s\S]*app\.use\(fncpGatewayMiddleware\);[\s\S]*app\.use\(writeDefaultHead\);[\s\S]*app\.use\(createResponseCompression\(\)\);/
    );
    expect(appSource).toContain("requestTimeout(15_000)");
    expect(appSource).not.toMatch(/from\s+["']connect-timeout["']/u);
    expect(serverMiddlewareSource).toContain('error.code = "ETIMEDOUT"');
    expect(serverMiddlewareSource).toContain("error.timeout = delayMs");
  });
});
