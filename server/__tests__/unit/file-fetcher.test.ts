import http from "node:http";
import { Readable, Writable } from "node:stream";
import { finished } from "node:stream/promises";

import { describe, expect, jest, test } from "@jest/globals";

import { makeFileFetcher } from "../../src/utils/file-fetcher";

describe("native static-file fetcher", () => {
  test("streams content and preserves preload, social-tag and header replacements", async () => {
    const upstream = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(
        '<script>"REPLACE_THIS_WITH_PRELOAD_DATA"</script>' +
          "<!-- REPLACE_THIS_WITH_FB_META_TAGS -->"
      );
    });
    await new Promise<void>((resolve) => {
      upstream.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = upstream.address();
      if (!address || typeof address === "string") {
        throw new Error("Synthetic upstream did not bind a TCP port.");
      }
      const chunks: Buffer[] = [];
      const response = new Writable({
        write(chunk, _encoding, callback) {
          chunks.push(Buffer.from(chunk));
          callback();
        },
      }) as Writable & { set: ReturnType<typeof jest.fn> };
      response.set = jest.fn();
      const done = finished(response);
      const fetchFile = makeFileFetcher(
        "127.0.0.1",
        address.port,
        "/index.html",
        { "Content-Type": "text/html" },
        {
          conversation: {
            topic: "Policy & priorities",
            description: 'A "shared" description',
          } as any,
        }
      );

      fetchFile(
        Object.assign(Readable.from([]), {
          headers: { host: "pulse.example.test" },
          path: "/9synthetic",
        }) as any,
        response
      );
      await done;

      const body = Buffer.concat(chunks).toString("utf8");
      expect(response.set).toHaveBeenCalledWith({
        "Content-Type": "text/html",
      });
      expect(body).not.toContain("REPLACE_THIS_WITH_PRELOAD_DATA");
      expect(body).toContain('"topic":"Policy & priorities"');
      expect(body).toContain(
        '<meta property="og:title" content="Policy &amp; priorities" />'
      );
      expect(body).toContain(
        '<meta property="og:description" content="A &quot;shared&quot; description" />'
      );
    } finally {
      await new Promise<void>((resolve, reject) => {
        upstream.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  test("preserves upstream non-success response bodies", async () => {
    const upstream = http.createServer((_req, res) => {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("synthetic-not-found");
    });
    await new Promise<void>((resolve) => {
      upstream.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = upstream.address();
      if (!address || typeof address === "string") {
        throw new Error("Synthetic upstream did not bind a TCP port.");
      }
      const chunks: Buffer[] = [];
      const response = new Writable({
        write(chunk, _encoding, callback) {
          chunks.push(Buffer.from(chunk));
          callback();
        },
      }) as Writable & { set: ReturnType<typeof jest.fn> };
      response.set = jest.fn();
      const done = finished(response);

      makeFileFetcher("127.0.0.1", address.port, "/missing", {
        "Content-Type": "text/plain",
      })(
        Object.assign(Readable.from([]), {
          headers: {},
          path: "/missing",
        }) as any,
        response
      );
      await done;

      expect(Buffer.concat(chunks).toString("utf8")).toContain(
        "synthetic-not-found"
      );
    } finally {
      await new Promise<void>((resolve, reject) => {
        upstream.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
