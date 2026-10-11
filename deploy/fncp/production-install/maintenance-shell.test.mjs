import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { FRESH_VOLUME_GUARD, postgresInitializationPlan } from './postgres-initialize.mjs';
import { renderProductionCompose } from '../production-deployment/compose.mjs';
import { composeRawShellCommand, MARIADB_FRESH_INITIALIZE } from './maintenance-shell.mjs';

export function fixture() {
  const configuration={version:2,profile:'FNCP_PRODUCTION_COMPOSE_V2',deployment:'fncp-compose-shell-test',platform:'linux/arm64',stateDirectory:'/private/fncp-test/core',sourceRevision:'a'.repeat(40),
    database:{name:'polis',owner:'polis_owner',migrationRole:'polis_migration',runtimeRole:'polis_runtime',mathRole:'polis_math',host:'postgres',port:5432},binding:{conversationId:'9freshClosedRound',statementIds:Array.from({length:15},(_,i)=>i)},
    identity:{issuer:'https://issuer.example.invalid/',audience:'configured-client',jwksUri:'https://issuer.example.invalid/jwks'},edge:{publicOrigin:'https://pulse.example.invalid',discardCookies:[]}};
  const imageLock={version:2,sourceRevision:configuration.sourceRevision,sourceFingerprint:'b'.repeat(64),images:Object.fromEntries(['api','math','postgres','migration','participant','wordpress','mariadb','proxy','edge'].map((r,i)=>[r,'sha256:'+String(i+1).repeat(64)]))};
  const owner='c'.repeat(48), statements=Array.from({length:15},(_,i)=>'Invented statement '+i);
  return {configuration,imageLock,owner,plan:postgresInitializationPlan(configuration,imageLock,owner,{statements,seedSha256:createHash('sha256').update(JSON.stringify(statements)).digest('hex'),topic:'Synthetic',description:'Synthetic initialization.'})};
}

test('fresh-volume shell guard survives the explicit Compose boundary', () => {
  const {plan}=fixture(), raw=structuredClone(plan.maintenance.initialize.command);
  const command=composeRawShellCommand(raw);
  assert.equal(command[0],'-c');assert.ok(command[1].includes('"$$root"'));
  assert.ok(command[1].includes('"$$(stat -c'));
  assert.ok(command[1].includes('"$$#"'));
  assert.equal(command[1].split('$$').join('$'),FRESH_VOLUME_GUARD);
  assert.deepEqual(raw,plan.maintenance.initialize.command);
});
test('seed environment credentials remain container-shell references through Compose', () => {
  const {plan}=fixture(), command=composeRawShellCommand(plan.maintenance.seed.command);
  for(const variable of ['PGSSLMODE','FNCP_DATABASE_HOST','FNCP_DATABASE_PORT','PGSSLROOTCERT','FNCP_DATABASE_PASSWORD'])
    assert.ok(command[1].includes('$$'+variable),variable);
  assert.equal(command[1].split('$$').join('$'),plan.maintenance.seed.command[1]);
  assert.ok(command[1].includes('unset FNCP_DATABASE_PASSWORD DATABASE_URL PGOPTIONS'));
});
test('MariaDB empty-directory substitution is evaluated only inside the container', () => {
  assert.equal(composeRawShellCommand(['-euc',MARIADB_FRESH_INITIALIZE])[1],MARIADB_FRESH_INITIALIZE.replace('$(ls',()=>'$$(ls'));
});
test('raw shell positional/braced/PID references are escaped exactly once at this boundary', () => {
  assert.deepEqual(composeRawShellCommand(['-c','echo "$1 ${value} $(id) $$"']),['-c','echo "$$1 $${value} $$(id) $$$$"']);
});
test('normal descriptors and the migration image command are not reescaped', () => {
  const {configuration,imageLock,owner,plan}=fixture(),before=renderProductionCompose(configuration,imageLock,owner);
  composeRawShellCommand(plan.maintenance.initialize.command);composeRawShellCommand(plan.maintenance.seed.command);
  assert.deepEqual(renderProductionCompose(configuration,imageLock,owner),before);
  assert.deepEqual(plan.maintenance.migration,before.services.migration);
  assert.ok(before.services.wordpress.healthcheck.test.at(-1).includes('$$s='));
});
test('the raw-shell boundary rejects ordinary command argv and malformed scripts', () => {
  for(const command of [['start'],['node','app.mjs'],['-c',''],['-c','x\0y'],['-c',42],['-c','echo ok','extra']])
    assert.throws(()=>composeRawShellCommand(command),/FNCP_MAINTENANCE_SHELL_REJECTED/u);
});
