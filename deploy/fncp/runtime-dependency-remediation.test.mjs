import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "../..");
const serverPackage = JSON.parse(
  readFileSync(resolve(root, "server/package.json"), "utf8"),
);
const serverLock = JSON.parse(
  readFileSync(resolve(root, "server/package-lock.json"), "utf8"),
);
const serverSource = readFileSync(
  resolve(root, "server/src/server.ts"),
  "utf8",
);
const dataExportSource = readFileSync(
  resolve(root, "server/src/routes/dataExport.ts"),
  "utf8",
);
const mathDependencies = readFileSync(
  resolve(root, "math/deps.edn"),
  "utf8",
);

test("server production dependencies use the reviewed fixed versions", () => {
  const expected = {
    "@google-cloud/translate": "9.4.2",
    "@google/genai": "2.13.0",
    auth0: "4.37.1",
    diff: "8.0.3",
    "response-time": "2.3.4",
    uuid: "11.1.1",
  };

  for (const [name, version] of Object.entries(expected)) {
    assert.equal(serverPackage.dependencies[name], version);
    assert.equal(serverLock.packages[""].dependencies[name], version);
  }

  assert.equal(serverPackage.overrides.socks, "2.8.9");
  assert.equal(serverLock.packages["node_modules/socks"].version, "2.8.9");
  assert.equal(serverLock.packages["node_modules/on-headers"].version, "1.1.0");
});

test("unused monolithic cloud clients stay outside the server closure", () => {
  for (const name of [
    "aws-sdk",
    "@google-cloud/aiplatform",
    "@google-cloud/vertexai",
    "googleapis",
  ]) {
    assert.equal(serverPackage.dependencies[name], undefined);
    assert.equal(serverLock.packages[`node_modules/${name}`], undefined);
  }
  assert.doesNotMatch(serverSource, /from ["']aws-sdk["']/u);
});

test("data-export signing uses the bounded AWS SDK v3 path", () => {
  assert.match(
    dataExportSource,
    /import \{ GetObjectCommand, S3Client \} from "@aws-sdk\/client-s3";/u,
  );
  assert.match(
    dataExportSource,
    /import \{ getSignedUrl \} from "@aws-sdk\/s3-request-presigner";/u,
  );
  assert.match(dataExportSource, /const s3Client = new S3Client\(/u);
  assert.match(dataExportSource, /await getSignedUrl\(/u);
  assert.match(dataExportSource, /new GetObjectCommand\(/u);
  assert.match(dataExportSource, /polis_err_data_export_results/u);
  assert.doesNotMatch(dataExportSource, /getSignedUrl\("getObject"/u);
});

test("math runtime removes the unused spreadsheet dependency and pins fixes", () => {
  assert.match(
    mathDependencies,
    /techascent\/tech\.ml\.dataset \{[\s\S]*?:exclusions \[[\s\S]*?org\.apache\.poi\/poi-ooxml\]\}/u,
  );
  assert.match(
    mathDependencies,
    /com\.fasterxml\.jackson\.core\/jackson-databind \{:mvn\/version "2\.21\.5"\}/u,
  );
  assert.match(
    mathDependencies,
    /com\.google\.guava\/guava \{:mvn\/version "32\.0\.0-android"\}/u,
  );
  assert.match(
    mathDependencies,
    /ch\.qos\.logback\/logback-classic \{:mvn\/version "1\.5\.34"\}/u,
  );
  assert.match(
    mathDependencies,
    /ch\.qos\.logback\/logback-core \{:mvn\/version "1\.5\.34"\}/u,
  );
});
