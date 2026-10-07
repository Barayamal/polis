import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildVotes, renderSql, spec } from './dedicated-analysis-fixture.mjs';
const input = { database: 'synthetic_polis', zid: 1, participantIds: Array.from({length:18}, (_,i)=>i), statementIds:Array.from({length:15},(_,i)=>i) };
test('fixture stays below identity cap and has deterministic non-degenerate vote totals', () => {
  const votes=buildVotes(input);
  assert.equal(spec.participantCount,18); assert.ok(spec.participantCount<=spec.identityCap);
  assert.equal(votes.length,270); assert.equal(new Set(votes.map(v=>`${v.pid}:${v.tid}`)).size,270);
  for (const tid of input.statementIds) {
    const chosen=votes.filter(v=>v.tid===tid);
    assert.equal(chosen.length,18); assert.equal(chosen.filter(v=>v.vote===-1).length,tid>=5&&tid<10?12:6);
  }
  assert.deepEqual(buildVotes(input),votes);
});
test('fixture refuses cap changes, duplicate identities and injected database input', () => {
  for (const change of [{participantIds:[...input.participantIds,18]}, {participantIds:input.participantIds.map(()=>0)}, {statementIds:input.statementIds.slice(1)}, {database:"synthetic';DROP"}, {zid:0}, {unsafe:true}])
    assert.throws(()=>renderSql({...input,...change}),/SYNTHETIC_MATH_FIXTURE_INPUT_INVALID/);
});
test('SQL insertion requires the exact empty closed synthetic subject and has no cleanup operations', () => {
  const sql=renderSql(input);
  assert.match(sql,/current_database\(\) <> 'synthetic_polis'/); assert.match(sql,/is_active=false/);
  assert.match(sql,/mod=1 AND is_meta=false AND active=true/); assert.match(sql,/EXISTS \(SELECT 1 FROM public.votes/);
  assert.match(sql,/BEGIN ISOLATION LEVEL SERIALIZABLE/); assert.doesNotMatch(sql,/\b(?:DELETE|TRUNCATE|DROP|CREATE ROLE|CREATE USER)\b/);
});
test('vote fixture works with the Pol.is multi-query insert rule and checks actual persisted counts before commit', () => {
  const schema=readFileSync(new URL('../../server/postgres/migrations/000000_initial.sql',import.meta.url),'utf8');
  assert.match(schema,/CREATE RULE on_vote_insert_update_unique_table AS\s+ON INSERT TO votes\s+DO ALSO\s+INSERT INTO votes_latest_unique/);
  const sql=renderSql(input);
  assert.doesNotMatch(sql,/^WITH\s/im);
  assert.match(sql,/INSERT INTO public\.votes\(zid,pid,tid,vote,created\)\s+SELECT 1,pid,tid,vote,now_as_millis\(\)-1000\+ordinal\s+FROM \(VALUES/);
  assert.match(sql,/count\(\*\) FROM public\.votes WHERE zid=1\) <> 270/);
  assert.match(sql,/count\(DISTINCT pid\) FROM public\.votes WHERE zid=1\) <> 18/);
  assert.match(sql,/count\(DISTINCT tid\) FROM public\.votes WHERE zid=1\) <> 15/);
  assert.match(sql,/count\(DISTINCT \(pid,tid\)\) FROM public\.votes WHERE zid=1\) <> 270/);
  assert.match(sql,/count\(\*\) FROM public\.votes_latest_unique WHERE zid=1\) <> 270/);
  assert.ok(sql.indexOf("RAISE EXCEPTION 'SYNTHETIC_MATH_FIXTURE_RESULT_REJECTED'")<sql.lastIndexOf('COMMIT;'));
});
