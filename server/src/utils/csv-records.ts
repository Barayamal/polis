import { parse, Parser } from "csv-parse";
import { parse as parseSync } from "csv-parse/sync";

/** Shared, tested CSV shapes; validation of business fields remains with callers. */
export function parseCsvRecords(input: string): Record<string, string>[] {
  return parseSync(input, {
    columns: true,
    skip_empty_lines: true,
  });
}

/** Preserve the vote worker's strict-width, trimmed streaming input. */
export function createVoteImportCsvParser(): Parser {
  return parse({ columns: true, trim: true, skip_empty_lines: true });
}

/** The upstream experimental topics reader deliberately permits uneven rows. */
export function createTopicCsvParser(): Parser {
  return parse({
    columns: true,
    skip_empty_lines: true,
    relax_column_count: true,
  });
}
