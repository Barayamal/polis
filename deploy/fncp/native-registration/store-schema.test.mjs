import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { SCHEMA, COLUMNS, assertNativeFoundationSchema } from './store-schema.mjs';

function database(t, schema = SCHEMA) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  db.exec('PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;');
  if (schema) db.exec(schema);
  return db;
}

const rejectsSchema = (db) => assert.throws(() => assertNativeFoundationSchema(db), { code: 'NATIVE_FOUNDATION_SCHEMA_MISMATCH' });

test('fresh exact STRICT schema passes with all expected columns and eight generated indexes', (t) => {
  const db = database(t);
  assert.equal(assertNativeFoundationSchema(db), true);
  assert.equal(db.prepare("SELECT count(*) AS total FROM sqlite_schema WHERE type='index'").get().total, 8);
  for (const [table, names] of Object.entries(COLUMNS)) {
    assert.deepEqual(db.prepare(`PRAGMA table_info(${table})`).all().map(({ name }) => name), names);
    assert.equal(db.prepare('PRAGMA table_list').all().find(({ name }) => name === table).strict, 1);
  }
});

test('schema contract arrays cannot be mutated by callers', () => {
  assert.ok(Object.isFrozen(COLUMNS));
  for (const columns of Object.values(COLUMNS)) assert.ok(Object.isFrozen(columns));
  assert.throws(() => COLUMNS.meta.push('foreign_column'), TypeError);
});

test('assertion rejects invalid, closed or empty database handles', (t) => {
  for (const value of [undefined, null, {}, { prepare: 3 }]) rejectsSchema(value);
  const db = database(t, '');
  rejectsSchema(db);
  const closed = new DatabaseSync(':memory:');
  closed.close();
  rejectsSchema(closed);
});

test('foreign store with matching table count cannot pass', (t) => {
  const foreignSchema = Object.keys(COLUMNS).map((table) => `CREATE TABLE ${table}(foreign_value TEXT) STRICT;`).join('\n');
  const db = database(t, foreignSchema);
  assert.equal(db.prepare("SELECT count(*) AS total FROM sqlite_schema WHERE type='table'").get().total, Object.keys(COLUMNS).length);
  rejectsSchema(db);
});

for (const [label, transform] of [
  ['non-STRICT table', (sql) => sql.replace('fault_code TEXT) STRICT', 'fault_code TEXT)')],
  ['extra column', (sql) => sql.replace('fault_code TEXT)', 'fault_code TEXT,foreign_data TEXT)')],
  ['renamed column', (sql) => sql.replace('request_sha TEXT NOT NULL', 'other_sha TEXT NOT NULL')],
  ['changed column order', (sql) => sql.replace('body TEXT NOT NULL,digest TEXT NOT NULL', 'digest TEXT NOT NULL,body TEXT NOT NULL')],
  ['changed column type', (sql) => sql.replace('config_sha TEXT NOT NULL', 'config_sha BLOB NOT NULL')],
  ['nullable required column', (sql) => sql.replace('profile TEXT NOT NULL', 'profile TEXT')],
  ['added default', (sql) => sql.replace('version INTEGER NOT NULL', 'version INTEGER NOT NULL DEFAULT 0')],
  ['removed account uniqueness', (sql) => sql.replace('account_id TEXT NOT NULL UNIQUE', 'account_id TEXT NOT NULL')],
  ['removed receipt uniqueness', (sql) => sql.replace('registration_ref TEXT NOT NULL UNIQUE REFERENCES registrations', 'registration_ref TEXT NOT NULL REFERENCES registrations')],
  ['removed event uniqueness', (sql) => sql.replace('event_ref TEXT NOT NULL UNIQUE', 'event_ref TEXT NOT NULL')],
  ['changed state check', (sql) => sql.replace("'pending','approved','revoked'", "'pending','approved','revoked','active'")],
  ['removed version check', (sql) => sql.replace(' CHECK(version>=0)', '')],
  ['changed event kind', (sql) => sql.replace("'register','approve','decline','revoke'", "'register','approve','decline','revoke','grant'")],
  ['changed removal state', (sql) => sql.replace("CHECK(state='pending')", "CHECK(state IN('pending','done'))")],
  ['changed FK target', (sql) => sql.replace('REFERENCES registrations(registration_ref)', 'REFERENCES registrations(account_id)')],
  ['cascade deletion', (sql) => sql.replace('REFERENCES registrations(registration_ref)', 'REFERENCES registrations(registration_ref) ON DELETE CASCADE')],
  ['case-insensitive unique key', (sql) => sql.replace('account_id TEXT NOT NULL UNIQUE', 'account_id TEXT COLLATE NOCASE NOT NULL UNIQUE')],
]) {
  test(`assertion rejects ${label}`, (t) => rejectsSchema(database(t, transform(SCHEMA))));
}

for (const [label, sql] of [
  ['unrelated table', 'CREATE TABLE foreign_store(value TEXT) STRICT;'],
  ['user index', 'CREATE INDEX extra_index ON registrations(state);'],
  ['partial user index', "CREATE UNIQUE INDEX extra_index ON registrations(request_sha) WHERE state='approved';"],
  ['view', 'CREATE VIEW registration_view AS SELECT state FROM registrations;'],
  ['trigger', "CREATE TRIGGER extra_trigger AFTER INSERT ON registrations BEGIN UPDATE meta SET fault_code='foreign'; END;"],
  ['TEMP table', 'CREATE TEMP TABLE foreign_temp(value TEXT);'],
  ['TEMP view', 'CREATE TEMP VIEW foreign_view AS SELECT state FROM registrations;'],
  ['TEMP trigger', "CREATE TEMP TRIGGER foreign_trigger AFTER INSERT ON registrations BEGIN SELECT 1; END;"],
]) {
  test(`assertion rejects ${label}`, (t) => {
    const db = database(t);
    db.exec(sql);
    rejectsSchema(db);
  });
}

test('assertion rejects attached stores without inspecting their application rows', (t) => {
  const db = database(t);
  db.exec("ATTACH DATABASE ':memory:' AS unrelated;");
  rejectsSchema(db);
});

test('assertion is read-only and does not implicitly enable foreign-key enforcement', (t) => {
  const db = database(t);
  db.exec('PRAGMA foreign_keys=OFF;');
  const before = db.prepare('PRAGMA schema_version').get().schema_version;
  assert.equal(assertNativeFoundationSchema(db), true);
  assert.equal(db.prepare('PRAGMA schema_version').get().schema_version, before);
  assert.equal(db.prepare('PRAGMA foreign_keys').get().foreign_keys, 0);
  for (const table of Object.keys(COLUMNS)) assert.equal(db.prepare(`SELECT count(*) AS total FROM ${table}`).get().total, 0);
});

function registration(db, ref = 'invented-registration', account = 'invented-account') {
  db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run(ref, account, 'invented-request-sha', 'pending', 0);
}

function event(db, sequence = 1, ref = 'invented-event', registrationRef = 'invented-registration', kind = 'register', version = 0) {
  db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(sequence, ref, registrationRef, kind, version, 'invented-request-sha', '{}', 'invented-digest', 'invented-previous-digest');
}

test('constraints enforce registration state, nonnegative versions and unique opaque account IDs', (t) => {
  const db = database(t);
  registration(db);
  assert.throws(() => registration(db, 'invented-second'));
  assert.throws(() => db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run('other', 'other-account', 'sha', 'active', 0));
  assert.throws(() => db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run('other', 'other-account', 'sha', 'pending', -1));
  assert.throws(() => db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run(null, 'other-account', 'sha', 'pending', 0));
  assert.throws(() => db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?)').run('other', 'other-account', 'sha', 'pending', 'not-an-integer'));
  assert.equal(assertNativeFoundationSchema(db), true);
});

test('meta restricts the singleton and STRICT types', (t) => {
  const db = database(t);
  const insert = db.prepare('INSERT INTO meta VALUES(?,?,?,?,?,?,?,?)');
  assert.throws(() => insert.run(2, 'synthetic', 'sha', 'key', 0, 0, 'sha', null));
  assert.throws(() => insert.run(1, 'synthetic', 'sha', 'key', 'bad-clock', 0, 'sha', null));
  insert.run(1, 'synthetic', 'sha', 'key', 0, 0, 'sha', null);
  assert.throws(() => insert.run(1, 'synthetic', 'sha', 'key', 0, 0, 'sha', null));
});

test('receipt foreign keys and one-receipt-per-registration uniqueness are enforced', (t) => {
  const db = database(t);
  const insert = db.prepare('INSERT INTO receipts VALUES(?,?,?,?)');
  assert.throws(() => insert.run('invented-receipt', 'missing-registration', '{}', 'sha'));
  registration(db);
  insert.run('invented-receipt', 'invented-registration', '{}', 'sha');
  assert.throws(() => insert.run('invented-receipt-2', 'invented-registration', '{}', 'sha'));
  assert.throws(() => db.prepare('DELETE FROM registrations WHERE registration_ref=?').run('invented-registration'));
  assert.equal(db.prepare('SELECT count(*) AS total FROM receipts').get().total, 1);
});

test('event kinds, uniqueness, versions and parent linkage are enforced without cascades', (t) => {
  const db = database(t);
  assert.throws(() => event(db));
  registration(db);
  event(db);
  assert.throws(() => event(db, 2));
  assert.throws(() => event(db, 2, 'invented-event-2', 'invented-registration', 'grant'));
  assert.throws(() => event(db, 2, 'invented-event-2', 'invented-registration', 'approve', -1));
  for (const [sequence, kind] of [[2, 'approve'], [3, 'decline'], [4, 'revoke']]) event(db, sequence, `invented-event-${sequence}`, 'invented-registration', kind, sequence - 1);
  assert.throws(() => db.prepare('DELETE FROM registrations WHERE registration_ref=?').run('invented-registration'));
  assert.equal(db.prepare('SELECT count(*) AS total FROM events').get().total, 4);
});

test('removal jobs remain pending with unique event and registration references', (t) => {
  const db = database(t);
  registration(db);
  event(db);
  const insert = db.prepare('INSERT INTO removal_jobs VALUES(?,?,?,?)');
  assert.throws(() => insert.run('invented-job', 'invented-registration', 'missing-event', 'pending'));
  assert.throws(() => insert.run('invented-job', 'missing-registration', 'invented-event', 'pending'));
  assert.throws(() => insert.run('invented-job', 'invented-registration', 'invented-event', 'done'));
  insert.run('invented-job', 'invented-registration', 'invented-event', 'pending');
  assert.throws(() => insert.run('invented-job-2', 'invented-registration', 'invented-event', 'pending'));
  registration(db, 'invented-registration-2', 'invented-account-2');
  assert.throws(() => insert.run('invented-job-2', 'invented-registration-2', 'invented-event', 'pending'));
  event(db, 2, 'invented-event-2', 'invented-registration', 'revoke', 1);
  assert.throws(() => insert.run('invented-job-2', 'invented-registration', 'invented-event-2', 'pending'));
  assert.throws(() => db.prepare('DELETE FROM events WHERE event_ref=?').run('invented-event'));
  assert.equal(db.prepare('SELECT count(*) AS total FROM removal_jobs').get().total, 1);
});
