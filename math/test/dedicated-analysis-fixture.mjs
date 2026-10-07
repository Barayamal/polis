import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const spec = JSON.parse(readFileSync(new URL('./fixtures/dedicated-analysis.json', import.meta.url), 'utf8'));
const invalid = () => { throw new Error('SYNTHETIC_MATH_FIXTURE_INPUT_INVALID'); };
const ids = (value, count) => Array.isArray(value) && value.length === count && new Set(value).size === count && value.every(x => Number.isInteger(x) && x >= 0 && x <= 2147483647);
export function buildVotes(input) {
  if (!input || Object.keys(input).sort().join(',') !== 'database,participantIds,statementIds,zid' ||
      !/^[a-z][a-z0-9_]{2,62}$/.test(input.database) || !Number.isInteger(input.zid) || input.zid < 1 || input.zid > 2147483647 ||
      !ids(input.participantIds, spec.participantCount) || !ids(input.statementIds, spec.statementCount)) invalid();
  return input.participantIds.flatMap((pid, i) => input.statementIds.map((tid, j) => ({
    zid: input.zid, pid, tid, vote: spec.profiles[Math.floor(i / spec.cohortSize)][j], ordinal: i * spec.statementCount + j,
  })));
}
export function renderSql(input) {
  const votes = buildVotes(input), pids = input.participantIds.join(','), tids = input.statementIds.join(','), zid = input.zid;
  return `-- ${spec.classification}
-- Owner-role fixture insertion only. This script does not create identities or prove API admission.
BEGIN ISOLATION LEVEL SERIALIZABLE;
SELECT zid FROM public.conversations WHERE zid=${zid} FOR UPDATE;
DO $fixture$
BEGIN
  IF current_database() <> '${input.database}'
     OR (SELECT count(*) FROM public.conversations WHERE zid=${zid} AND is_active=false) <> 1
     OR (SELECT count(*) FROM public.participants WHERE zid=${zid}) > ${spec.identityCap}
     OR (SELECT count(DISTINCT uid) FROM public.participants WHERE zid=${zid} AND pid IN (${pids})) <> ${spec.participantCount}
     OR (SELECT count(*) FROM public.comments WHERE zid=${zid}) <> ${spec.statementCount}
     OR (SELECT count(*) FROM public.comments WHERE zid=${zid} AND tid IN (${tids}) AND mod=1 AND is_meta=false AND active=true) <> ${spec.statementCount}
     OR EXISTS (SELECT 1 FROM public.votes WHERE zid=${zid})
     OR EXISTS (SELECT 1 FROM public.math_main WHERE zid=${zid})
  THEN RAISE EXCEPTION 'SYNTHETIC_MATH_FIXTURE_PREFLIGHT_REJECTED'; END IF;
END
$fixture$;
-- Pol.is rewrites vote inserts through an ON INSERT DO ALSO rule. PostgreSQL
-- rejects a top-level WITH on that path. The derived VALUES table is compatible
-- with the rule; now_as_millis() uses transaction-stable now(), so all ordinals
-- retain one clock origin even when the rule expands the statement.
INSERT INTO public.votes(zid,pid,tid,vote,created)
SELECT ${zid},pid,tid,vote,now_as_millis()-1000+ordinal
FROM (VALUES
${votes.map(v => `  (${v.pid},${v.tid},${v.vote},${v.ordinal})`).join(',\n')}) AS fixture(pid,tid,vote,ordinal);
DO $fixture_result$
BEGIN
  IF (SELECT count(*) FROM public.votes WHERE zid=${zid}) <> ${votes.length}
     OR (SELECT count(DISTINCT pid) FROM public.votes WHERE zid=${zid}) <> ${spec.participantCount}
     OR (SELECT count(DISTINCT tid) FROM public.votes WHERE zid=${zid}) <> ${spec.statementCount}
     OR (SELECT count(DISTINCT (pid,tid)) FROM public.votes WHERE zid=${zid}) <> ${votes.length}
     OR (SELECT max(created)-min(created) FROM public.votes WHERE zid=${zid}) <> ${votes.length - 1}
     OR (SELECT count(*) FROM public.votes_latest_unique WHERE zid=${zid}) <> ${votes.length}
  THEN RAISE EXCEPTION 'SYNTHETIC_MATH_FIXTURE_RESULT_REJECTED'; END IF;
END
$fixture_result$;
SELECT count(*) AS votes, count(DISTINCT pid) AS participants, count(DISTINCT tid) AS statements,
       min(created) AS first_vote_timestamp, max(created) AS last_vote_timestamp
FROM public.votes WHERE zid=${zid};
COMMIT;
`;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try { process.stdout.write(renderSql(JSON.parse(readFileSync(0, 'utf8')))); }
  catch { process.stderr.write('SYNTHETIC_MATH_FIXTURE_INPUT_INVALID\n'); process.exitCode = 1; }
}
