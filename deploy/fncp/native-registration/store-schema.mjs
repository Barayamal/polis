// Synthetic local foundation only. This schema is not an admission or auth grant.
// The caller must separately enable foreign_keys; this assertion is read-only.
const TABLES = Object.freeze({
  meta: "CREATE TABLE meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),profile TEXT NOT NULL,config_sha TEXT NOT NULL,account_key TEXT NOT NULL,last_ms INTEGER NOT NULL,sequence INTEGER NOT NULL,last_digest TEXT NOT NULL,fault_code TEXT) STRICT",
  registrations: "CREATE TABLE registrations(registration_ref TEXT PRIMARY KEY,account_id TEXT NOT NULL UNIQUE,request_sha TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('pending','approved','revoked')),version INTEGER NOT NULL CHECK(version>=0)) STRICT",
  receipts: "CREATE TABLE receipts(receipt_ref TEXT PRIMARY KEY,registration_ref TEXT NOT NULL UNIQUE REFERENCES registrations(registration_ref),body TEXT NOT NULL,digest TEXT NOT NULL) STRICT",
  events: "CREATE TABLE events(sequence INTEGER PRIMARY KEY,event_ref TEXT NOT NULL UNIQUE,registration_ref TEXT NOT NULL REFERENCES registrations(registration_ref),kind TEXT NOT NULL CHECK(kind IN('register','approve','decline','revoke')),version INTEGER NOT NULL CHECK(version>=0),request_sha TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,previous_digest TEXT NOT NULL) STRICT",
  removal_jobs: "CREATE TABLE removal_jobs(job_ref TEXT PRIMARY KEY,registration_ref TEXT NOT NULL UNIQUE REFERENCES registrations(registration_ref),event_ref TEXT NOT NULL UNIQUE REFERENCES events(event_ref),state TEXT NOT NULL CHECK(state='pending')) STRICT",
});

export const SCHEMA = `${Object.values(TABLES).join(';\n')};\n`;

export const COLUMNS = Object.freeze({
  meta: Object.freeze(['singleton', 'profile', 'config_sha', 'account_key', 'last_ms', 'sequence', 'last_digest', 'fault_code']),
  registrations: Object.freeze(['registration_ref', 'account_id', 'request_sha', 'state', 'version']),
  receipts: Object.freeze(['receipt_ref', 'registration_ref', 'body', 'digest']),
  events: Object.freeze(['sequence', 'event_ref', 'registration_ref', 'kind', 'version', 'request_sha', 'body', 'digest', 'previous_digest']),
  removal_jobs: Object.freeze(['job_ref', 'registration_ref', 'event_ref', 'state']),
});

const INTEGER_COLUMNS = new Set(['meta.singleton', 'meta.last_ms', 'meta.sequence', 'registrations.version', 'events.sequence', 'events.version']);
const PRIMARY_KEYS = Object.freeze({ meta: 'singleton', registrations: 'registration_ref', receipts: 'receipt_ref', events: 'sequence', removal_jobs: 'job_ref' });
const NULLABLE_COLUMNS = new Set(['meta.singleton', 'meta.fault_code', 'events.sequence']);
const INDEXES = Object.freeze({
  registrations: Object.freeze([
    Object.freeze({ name: 'sqlite_autoindex_registrations_1', column: 'registration_ref', origin: 'pk' }),
    Object.freeze({ name: 'sqlite_autoindex_registrations_2', column: 'account_id', origin: 'u' }),
  ]),
  receipts: Object.freeze([
    Object.freeze({ name: 'sqlite_autoindex_receipts_1', column: 'receipt_ref', origin: 'pk' }),
    Object.freeze({ name: 'sqlite_autoindex_receipts_2', column: 'registration_ref', origin: 'u' }),
  ]),
  events: Object.freeze([
    Object.freeze({ name: 'sqlite_autoindex_events_1', column: 'event_ref', origin: 'u' }),
  ]),
  removal_jobs: Object.freeze([
    Object.freeze({ name: 'sqlite_autoindex_removal_jobs_1', column: 'job_ref', origin: 'pk' }),
    Object.freeze({ name: 'sqlite_autoindex_removal_jobs_2', column: 'registration_ref', origin: 'u' }),
    Object.freeze({ name: 'sqlite_autoindex_removal_jobs_3', column: 'event_ref', origin: 'u' }),
  ]),
});
const FOREIGN_KEYS = Object.freeze({
  receipts: Object.freeze([{ from: 'registration_ref', table: 'registrations', to: 'registration_ref' }]),
  events: Object.freeze([{ from: 'registration_ref', table: 'registrations', to: 'registration_ref' }]),
  removal_jobs: Object.freeze([
    { from: 'event_ref', table: 'events', to: 'event_ref' },
    { from: 'registration_ref', table: 'registrations', to: 'registration_ref' },
  ]),
});

function mismatch() {
  const error = new Error('Native foundation schema does not match the exact synthetic profile');
  error.code = 'NATIVE_FOUNDATION_SCHEMA_MISMATCH';
  throw error;
}

function same(actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) mismatch();
}

/** Reject a foreign or extended store before reading its application rows. */
export function assertNativeFoundationSchema(db) {
  if (!db || typeof db.prepare !== 'function') mismatch();
  try {
    // Attached stores and TEMP objects must not become alternate data/logic paths.
    const databases = db.prepare('PRAGMA database_list').all();
    if (databases.some(({ name }) => name !== 'main' && name !== 'temp')) mismatch();
    if (db.prepare('SELECT name FROM sqlite_temp_schema').all().length !== 0) mismatch();

    const expectedObjects = Object.entries(TABLES).map(([name, sql]) => ({ type: 'table', name, tbl_name: name, sql }));
    for (const [table, indexes] of Object.entries(INDEXES)) {
      for (const { name } of indexes) expectedObjects.push({ type: 'index', name, tbl_name: table, sql: null });
    }
    const byName = (left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0;
    same(
      db.prepare('SELECT type,name,tbl_name,sql FROM main.sqlite_schema').all().map((row) => ({ ...row })).sort(byName),
      expectedObjects.sort(byName),
    );

    const tableList = db.prepare('PRAGMA main.table_list').all();
    for (const [table, columns] of Object.entries(COLUMNS)) {
      const tableMetadata = tableList.find((row) => row.schema === 'main' && row.name === table);
      if (!tableMetadata || tableMetadata.type !== 'table' || tableMetadata.ncol !== columns.length || tableMetadata.wr !== 0 || tableMetadata.strict !== 1) mismatch();
      // All identifiers below are constants, never caller-supplied SQL fragments.
      const actualColumns = db.prepare(`PRAGMA main.table_xinfo(${table})`).all().map((row) => ({ ...row }));
      const expectedColumns = columns.map((name, cid) => ({
        cid, name, type: INTEGER_COLUMNS.has(`${table}.${name}`) ? 'INTEGER' : 'TEXT',
        notnull: NULLABLE_COLUMNS.has(`${table}.${name}`) ? 0 : 1,
        dflt_value: null, pk: PRIMARY_KEYS[table] === name ? 1 : 0, hidden: 0,
      }));
      same(actualColumns, expectedColumns);

      const expectedIndexes = INDEXES[table] ?? [];
      const actualIndexes = db.prepare(`PRAGMA main.index_list(${table})`).all()
        .map(({ name, unique, origin, partial }) => ({ name, unique, origin, partial })).sort(byName);
      same(actualIndexes, expectedIndexes.map(({ name, origin }) => ({ name, unique: 1, origin, partial: 0 })).sort(byName));
      for (const { name, column } of expectedIndexes) {
        const cid = columns.indexOf(column);
        same(db.prepare(`PRAGMA main.index_xinfo(${name})`).all().map((row) => ({ ...row })), [
          { seqno: 0, cid, name: column, desc: 0, coll: 'BINARY', key: 1 },
          { seqno: 1, cid: -1, name: null, desc: 0, coll: 'BINARY', key: 0 },
        ]);
      }

      const actualForeignKeys = db.prepare(`PRAGMA main.foreign_key_list(${table})`).all()
        .map(({ seq, table: target, from, to, on_update, on_delete, match }) => ({ seq, table: target, from, to, on_update, on_delete, match }))
        .sort((left, right) => left.from < right.from ? -1 : left.from > right.from ? 1 : 0);
      const expectedForeignKeys = (FOREIGN_KEYS[table] ?? []).map(({ from, table: target, to }) => ({
        seq: 0, table: target, from, to, on_update: 'NO ACTION', on_delete: 'NO ACTION', match: 'NONE',
      }));
      same(actualForeignKeys, expectedForeignKeys);
    }
    return true;
  } catch (error) {
    if (error?.code === 'NATIVE_FOUNDATION_SCHEMA_MISMATCH') throw error;
    // No foreign SQL text or application contents are included in failures.
    mismatch();
  }
}
