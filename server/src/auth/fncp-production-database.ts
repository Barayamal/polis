/** Read-only readiness for the dedicated participant process. No database or
 * application module is imported here; callers supply the real primary query.
 */
import { loadFncpGatewayConfig } from "./fncp-gateway";

type Query = (sql: string, params: any[]) => Promise<unknown>;
const failed = () => new Error("FNCP_PRODUCTION_DATABASE_NOT_READY");

export async function assertFncpProductionDatabaseReady(query: Query, env: NodeJS.ProcessEnv): Promise<void> {
  try {
    const url = new URL(env.DATABASE_URL!);
    const role = decodeURIComponent(url.username);
    const database = decodeURIComponent(url.pathname.slice(1));
    const metadata = await query(`SELECT (
      current_database() = $1 AND current_user = $2
      AND NOT pg_is_in_recovery() AND current_setting('transaction_read_only') = 'off'
      AND COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false)
      AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
      AND NOT r.rolreplication AND NOT r.rolbypassrls
      AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = current_database() AND datdba = r.oid)
      AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
      AND NOT has_database_privilege(current_user, current_database(), 'TEMPORARY')
      AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname !~ '^pg_(toast|temp)'
        AND (nspowner = r.oid OR has_schema_privilege(current_user, oid, 'CREATE')))
      AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relowner = r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proowner = r.oid)
      AND to_regnamespace('fncp_deploy') IS NOT NULL
      AND NOT has_schema_privilege(current_user, to_regnamespace('fncp_deploy'), 'USAGE')
      AND has_table_privilege(current_user, to_regclass('public.fncp_provider_allowlist_operations'), 'SELECT,INSERT,UPDATE,DELETE')
    ) AS ready FROM pg_roles r WHERE r.rolname = current_user`, [database, role]) as { ready: boolean }[];
    if (metadata.length !== 1 || metadata[0].ready !== true) throw failed();

    const gateway = loadFncpGatewayConfig(env);
    const rows = await query(`SELECT c.is_active, c.use_xid_whitelist, c.is_data_open,
      ARRAY(SELECT s.tid FROM comments s WHERE s.zid = c.zid ORDER BY s.tid) AS tids,
      NOT EXISTS (SELECT 1 FROM comments s WHERE s.zid = c.zid
        AND (s.active IS NOT TRUE OR s.is_seed IS NOT TRUE OR s.mod <> 1)) AS seeds_ready
      FROM zinvites z JOIN conversations c ON c.zid = z.zid WHERE z.zinvite = $1`,
      [gateway.conversationId]) as { is_active: boolean; use_xid_whitelist: boolean;
        is_data_open: boolean; tids: number[]; seeds_ready: boolean }[];
    const row = rows[0];
    // A restart cannot reopen a public round. Operators close the round before
    // starting this participant process, then activate through the authority.
    if (rows.length !== 1 || row.is_active !== false || row.use_xid_whitelist !== true ||
        row.is_data_open !== false || row.seeds_ready !== true || !Array.isArray(row.tids) ||
        row.tids.length !== 15 || new Set(row.tids).size !== 15 ||
        row.tids.some(id => !Number.isSafeInteger(id) || !gateway.fixedStatementIds?.has(id))) throw failed();
  } catch { throw failed(); }
}
