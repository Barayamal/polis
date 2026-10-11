import { readFileSync } from 'node:fs';
import { validateConfiguration, fail } from './configuration.mjs';
import { renderSql } from '../../../math/test/dedicated-analysis-fixture.mjs';
const seeds=JSON.parse(readFileSync(new URL('../seed-statements.json',import.meta.url),'utf8'));
const quote=s=>"'"+s.replaceAll("'","''")+"'";
/** SQL-only engine/startup fixture. This does NOT prove registration, approval,
 * invitation, HTTP bootstrap or participant voting. No real accounts/data. */
export function localFixture(c){
 validateConfiguration(c);
 if(c.binding.statementIds.some((n,i)=>n!==i)||c.binding.conversationId!=='9fncpSelfhostFixture')throw fail('FIXTURE_BINDING');
 if(!Array.isArray(seeds)||seeds.length!==15||seeds.some(s=>typeof s!=='string'))throw fail('FIXTURE_SEEDS');
 const votesSql=renderSql({database:c.database.name,zid:1,participantIds:Array.from({length:18},(_,i)=>i+1),statementIds:c.binding.statementIds}).replace('BEGIN ISOLATION LEVEL SERIALIZABLE;\n','');
 return `BEGIN ISOLATION LEVEL SERIALIZABLE;
DO $fresh$
BEGIN
 IF current_database()<>${quote(c.database.name)} OR EXISTS(SELECT 1 FROM conversations) OR EXISTS(SELECT 1 FROM users)
 THEN RAISE EXCEPTION 'SELFHOST_FIXTURE_REQUIRES_EMPTY_DATABASE'; END IF;
END $fresh$;
INSERT INTO users(email,is_owner) VALUES ('seed-owner@selfhost.invalid',true);
INSERT INTO conversations(zid,owner,org_id,topic,description,is_active,is_public,is_data_open,use_xid_whitelist,xid_required,is_anon,is_draft,strict_moderation,profanity_filter,spam_filter,write_type,topics_enabled)
SELECT 1,uid,uid,'Synthetic self-host core fixture','SQL fixture only: no participant admission proof.',false,false,false,true,true,true,false,true,false,false,0,false FROM users;
SELECT setval(pg_get_serial_sequence('conversations','zid'),1,true);
INSERT INTO zinvites(zid,zinvite) VALUES(1,${quote(c.binding.conversationId)});
INSERT INTO participants(uid,zid) SELECT uid,1 FROM users;
INSERT INTO users(email,is_owner) SELECT 'synthetic-'||n||'@selfhost.invalid',false FROM generate_series(1,18) AS n;
INSERT INTO participants(uid,zid) SELECT uid,1 FROM users WHERE email<>'seed-owner@selfhost.invalid' ORDER BY uid;
INSERT INTO comments(zid,pid,uid,txt,is_seed,mod,is_meta,active)
SELECT 1,p.pid,p.uid,s.txt,true,1,false,true FROM participants p CROSS JOIN (VALUES
${seeds.map((s,i)=>`(${i},${quote(s)})`).join(',\n')}) AS s(ordinal,txt)
WHERE p.zid=1 AND p.pid=0 ORDER BY s.ordinal;
`+votesSql;
}
