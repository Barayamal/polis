import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const dockerfiles = [
  "server/Dockerfile",
  "server/Dockerfile-migrate",
  "client-participation-alpha/Dockerfile",
  "deploy/fncp/nginx/Dockerfile",
];

const contexts = [
  "server/busybox-fixed",
  "client-participation-alpha/busybox-fixed",
  "deploy/fncp/busybox-fixed",
];

const read = (path) => readFile(path, "utf8");
const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");

test("all four Alpine release Dockerfiles replace BusyBox", async () => {
  for (const path of dockerfiles) {
    const source = await read(path);
    assert.match(source, /AS fncp-busybox-fixed/u, path);
    assert.match(
      source,
      /COPY --from=fncp-busybox-fixed \/out\/busybox \/bin\/busybox/u,
      path,
    );
    assert.match(
      source,
      /org\.barayamal\.fncp\.busybox\.remediation="CVE-2025-60876-upstream-patch"/u,
      path,
    );
    assert.match(source, /build-base=0\.5-r4/u, path);
    assert.match(source, /utmps-static=0\.1\.3\.3-r0/u, path);
    assert.match(
      source,
      /test "\$\(readlink -f \/bin\/sh\)" = \/bin\/busybox/u,
      path,
    );
    assert.match(
      source,
      /test "\$\(readlink -f \/usr\/bin\/wget\)" = \/bin\/busybox/u,
      path,
    );
    assert.match(
      source,
      /Unencoded control character found in the URL!/u,
      path,
    );
  }
});

test("all build contexts carry identical patch bytes and pinned inputs", async () => {
  const patches = await Promise.all(
    contexts.map((path) => read(`${path}/CVE-2025-60876.patch`)),
  );
  assert.equal(new Set(patches.map(sha256)).size, 1);

  const scripts = await Promise.all(
    contexts.map((path) => read(`${path}/build-fixed-busybox.sh`)),
  );
  for (const source of scripts) {
    assert.match(
      source,
      /3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4/u,
    );
    assert.match(
      source,
      /c3ef5d10e6ef6528852c51f0564963e2f8c1be19/u,
    );
    assert.match(
      source,
      /0598ff6f34d8067a4e6663548961df3f2088f83f9a45810030b9d210ae53ef97/u,
    );
    assert.match(source, /Unencoded control character found in the URL!/u);
    assert.match(source, /static-pie linked/u);
    assert.match(source, /Requesting program interpreter/u);
  }
});
