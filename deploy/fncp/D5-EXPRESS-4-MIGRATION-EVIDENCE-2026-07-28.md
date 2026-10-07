# FNCP Option C D5 supported Express migration evidence — 28 July 2026

## Scope and decision

This bounded pass replaces end-of-life Express 3.21.2 and its bundled
Connect 2/multiparty stack with exact Express 4.22.2. The Express project lists
both the 4.x and 5.x release lines as supported, but supports only the latest
release within each major line. Express 4.22.2 is therefore the smallest
supported migration from this application’s legacy route and request
semantics.

Express 5 was not selected for this pass. Its route-path, wildcard, response
and `req.body` changes would combine a second framework migration with the
removal of Connect. That remains a future, separately tested improvement
rather than a reason to keep an end-of-life framework in this candidate.

Primary references:

- <https://expressjs.com/en/support/>
- <https://expressjs.com/en/guide/migrating-4/>
- <https://expressjs.com/en/guide/migrating-5/>

## Exact replacement

| Previous runtime | Candidate runtime |
|---|---|
| `express@3.21.2` | exact `express@4.22.2` |
| `express.bodyParser()` | `express.json()` and `express.urlencoded()` |
| bundled Connect cookie parser | exact `cookie-parser@1.4.7` |
| bundled Connect compression | exact `compression@1.8.1` |
| implicit Connect multipart temp-file parsing | explicit `415 polis_err_multipart_not_supported` |

The reviewed body contract retains:

- the existing 50 MB JSON and URL-encoded limits;
- `application/json` and `application/*+json`;
- nested URL-encoded fields through `extended: true`;
- cookies before the FNCP gateway;
- the existing gateway, default-header and compression order; and
- streamed-response `flush()` typing supplied by the explicit compression
  middleware.

Repository-wide source inspection found no server use of `req.files` and no
multipart request route. The administration CSV controls read files in the
browser and send API data, rather than uploading a multipart body. Rejecting
multipart is therefore deliberate: it prevents silent temp-file parsing from
returning with a future dependency change and gives an unsupported client a
deterministic response.

### Post-migration middleware-order correction

Release review found that `globalErrorHandler` was registered before routes
that are installed asynchronously after the legacy helper bundle becomes
ready. In Express, error middleware must follow the routes whose errors it
handles. The handler now registers at the end of the successful
`helpersInitialized` callback, after every asynchronously installed route.

An actual Express-stack regression now leaves the timed route open and proves
that the request reaches the handler as the established `408` JSON response.
A production-source ordering contract separately proves that the error handler
follows the asynchronous route installation. The reverse-proxy comment was
also corrected to match the actual `trust proxy` value: one explicitly
configured hop, not a private-subnet trust rule.

## Production package audit change

| Server audit field | D4 baseline | D5 candidate | Change |
|---|---:|---:|---:|
| Production packages | 1,054 | 986 | -68 |
| Total package findings | 89 | 61 | -28 |
| Critical | 8 | 4 | -4 |
| High | 27 | 8 | -19 |
| Moderate | 44 | 43 | -1 |
| Low | 10 | 6 | -4 |
| Direct critical/high | 1 | 0 | -1 |

There are no npm production findings on `express`, `body-parser`,
`compression` or `cookie-parser`, and the candidate production tree contains
neither `connect` nor `multiparty`.

The remaining 61 findings are real residual blockers, not a production pass.
They include four critical and eight high transitive package findings across
other server capabilities. The production dependency gate therefore remains
closed even though the direct Express/Connect blocker is removed.

### Residual critical/high reachability

| Finding path | Candidate interpretation |
|---|---|
| AWS SDK clients → `fast-xml-parser` | Runtime clients are present; reachability has not been excluded |
| Google GAX → request types → `form-data` | Installed production path; runtime exploitability has not been proven or dismissed |
| `sql` → `lodash@4.1.0` | Runtime query-builder path; no automatic npm fix |
| Google GAX/proto loader → `protobufjs` | Runtime AI/translation path; FNCP disables those optional processors, but image-level removal has not been proven |
| Babel/Jest and sensemaking-tools → glob/YAML packages | Several build/test-shaped packages remain declared in the production tree; they need a separate dependency-classification pass |
| `@google/genai`/OpenAI → `ws` | Optional model-client path remains installed; configuration-off is not equivalent to image removal |
| `dd-trace` → `js-yaml` | Telemetry is explicitly off for FNCP, but the package remains in the image |
| `xmlbuilder2` → `js-yaml` | Runtime XML path remains installed and needs a reviewed major upgrade |

These are dependency-chain observations, not claims that a finding is
exploitable or unreachable. Only pruning the exact production image or testing
the affected capability can close each item.

The current server image build installs development dependencies for the
TypeScript compile and does not yet prune them from the runtime layer.
Consequently, the 61-finding `--omit=dev` audit is a source-tree production
dependency view, not an SBOM-equivalent claim about the exact image.

## Verification

- TypeScript build: **PASS**;
- lint: **PASS**;
- pre-correction supported middleware, dependency contract, FNCP gateway and
  timeout checkpoint: **31/31 PASS**;
- post-correction focused middleware/error-order suite: **19/19 PASS**;
- request-timeout file, including the actual Express-stack `408` and
  production-source ordering regressions: **8/8 PASS**;
- JSON suffix, nested URL-encoded, cookie, compression and explicit multipart
  rejection behavior: **4/4 PASS**;
- lockfile inventory: Express 4.22.2 present; Connect and multiparty absent;
- production audit: 61 findings, with no direct critical/high finding.

The post-correction deliberately key-free, database-free unit invocation
passed 97 tests and left 12 known environment-fixture cases unresolved by the
missing database configuration and participant JWT keys. It is not a
whole-suite pass.

The broader nine-case disposable PostgreSQL/OIDC integration passed before
this ordering correction and has not yet been repeated. The corrected server
image was rebuilt and the clean cold-start matrix was repeated successfully:
it closed its synthetic conversation after observing allowed `200` plus
fail-closed `403` results for missing, invalid, OIDC-bypass, removed and
removed-warm-session access. Its SBOM and vulnerability scan have not yet been
regenerated, so the earlier image evidence cannot attest the corrected build.

Server lockfile SHA-256:
`be32934b26356ece4888cf3113c271c891ccece2453f8047a65b3d507ad126f0`.

## Decision

D5 removes the legacy Express/Connect critical blocker without changing the
FNCP private-gateway contract, and the ordering correction restores the
intended timeout-error path. It materially improves the candidate but does not
authorise an internet deployment or genuine participation. The
corrected-source cold-start gate is closed; the broader integration, fresh
image/SBOM, residual package, browser, operational and Australian production
ownership gates remain open.
