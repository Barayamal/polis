/**
 * Narrow PostgreSQL query builder for the legacy Pol.is table helpers.
 *
 * This intentionally implements only the query shapes used by the non-
 * experimental server. Identifiers are created from table definitions, object
 * writes are checked against those definitions, and values are either bound by
 * `toQuery()` or encoded with the same semantics as node-sql 0.78.0 by
 * `toString()`.
 */

export interface PostgresQuery {
  text: string;
  values: unknown[];
}

interface RenderContext {
  inlineValues: boolean;
  values: unknown[];
}

interface Renderable {
  render(context: RenderContext): string;
}

type QueryValue = unknown;
type InValue = readonly QueryValue[] | Query;

class TrustedSqlValue implements Renderable {
  constructor(private readonly sql: "now_as_millis()") {}

  render(_context: RenderContext): string {
    return this.sql;
  }
}

const DATABASE_NOW_AS_MILLIS = new TrustedSqlValue("now_as_millis()");

export function databaseNowAsMillis(): unknown {
  return DATABASE_NOW_AS_MILLIS;
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replace(/"/gu, '""')}"`;
}

function quoteValue(value: string, quoteCharacter = "'"): string {
  return `${quoteCharacter}${value
    .split(quoteCharacter)
    .join(quoteCharacter + quoteCharacter)}${quoteCharacter}`;
}

function inlineParameter(value: unknown, quoteCharacter = "'"): string {
  if (value === null) {
    return "NULL";
  }
  if (typeof value === "boolean") {
    return value ? "TRUE" : "FALSE";
  }
  if (typeof value === "number") {
    return String(value);
  }
  if (typeof value === "string") {
    return quoteValue(value, quoteCharacter);
  }
  if (typeof value !== "object") {
    throw new Error(`Unable to use ${String(value)} in query`);
  }

  if (Array.isArray(value)) {
    if (
      value.length > 0 &&
      typeof value[0] === "object" &&
      value[0] !== null &&
      !(value[0] instanceof Date) &&
      !Array.isArray(value[0])
    ) {
      // Preserve node-sql's historical array-of-object representation.
      return `'${JSON.stringify(value)}'`;
    }

    const items = value.map((item) => inlineParameter(item, '"'));
    return `'{${items.join(",")}}'`;
  }
  if (value instanceof Date) {
    return inlineParameter(value.toISOString());
  }
  if (Buffer.isBuffer(value)) {
    return inlineParameter(`\\x${value.toString("hex")}`);
  }

  const stringValue = value.toString();
  return inlineParameter(
    stringValue === "[object Object]" ? JSON.stringify(value) : stringValue
  );
}

function renderParameter(value: QueryValue, context: RenderContext): string {
  if (context.inlineValues) {
    return inlineParameter(value);
  }
  context.values.push(value);
  return `$${context.values.length}`;
}

function renderWriteValue(value: QueryValue, context: RenderContext): string {
  return value instanceof TrustedSqlValue
    ? value.render(context)
    : renderParameter(value, context);
}

abstract class Expression implements Renderable {
  abstract render(context: RenderContext): string;

  and(right: QueryValue): Expression {
    return new BinaryExpression(this, "AND", toExpression(right));
  }

  or(right: QueryValue): Expression {
    return new BinaryExpression(this, "OR", toExpression(right));
  }
}

class ParameterExpression extends Expression {
  constructor(private readonly value: QueryValue) {
    super();
  }

  render(context: RenderContext): string {
    return renderParameter(this.value, context);
  }

  isNull(): boolean {
    return this.value === null;
  }
}

class BinaryExpression extends Expression {
  constructor(
    private readonly left: Renderable,
    private readonly operator: string,
    private readonly right: Renderable
  ) {
    super();
  }

  render(context: RenderContext): string {
    return `(${this.left.render(context)} ${this.operator} ${this.right.render(
      context
    )})`;
  }
}

class UnaryExpression extends Expression {
  constructor(
    private readonly operand: Renderable,
    private readonly operator: string
  ) {
    super();
  }

  render(context: RenderContext): string {
    return `(${this.operand.render(context)} ${this.operator})`;
  }
}

class InExpression extends Expression {
  constructor(
    private readonly left: Column,
    private readonly right: InValue,
    private readonly negated: boolean
  ) {
    super();
  }

  render(context: RenderContext): string {
    const left = this.left.render(context);

    if (this.right instanceof Query) {
      const operator = this.negated ? "NOT IN" : "IN";
      return `(${left} ${operator} (${this.right.render(context)}))`;
    }

    if (this.right.length === 0) {
      return this.negated ? "(1=1)" : "(1=0)";
    }

    const parameters = this.right.map(
      (value) => new ParameterExpression(value)
    );
    const nonNullParameters = parameters.filter(
      (parameter) => !parameter.isNull()
    );
    const hasNull = nonNullParameters.length !== parameters.length;

    if (nonNullParameters.length === 0) {
      return this.negated ? `(${left} IS NOT NULL)` : `(${left} IS NULL)`;
    }

    const rendered = nonNullParameters
      .map((parameter) => parameter.render(context))
      .join(", ");
    if (!hasNull) {
      return `(${left} ${this.negated ? "NOT IN" : "IN"} (${rendered}))`;
    }

    const nullableIn = `${left} IN (${rendered}) OR ${left} IS NULL`;
    return this.negated ? `(NOT (${nullableIn}))` : `(${nullableIn})`;
  }
}

class StarExpression implements Renderable {
  constructor(private readonly table: Table) {}

  render(_context?: RenderContext): string {
    return `${quoteIdentifier(this.table.name)}.*`;
  }
}

class OrderExpression implements Renderable {
  constructor(
    private readonly value: Column,
    private readonly direction?: "DESC"
  ) {}

  render(context: RenderContext): string {
    const value = this.value.render(context);
    return this.direction ? `${value} ${this.direction}` : value;
  }
}

export class Column extends Expression {
  readonly descending: OrderExpression;
  readonly desc: OrderExpression;
  readonly ascending: Column;
  readonly asc: Column;

  constructor(readonly table: Table, readonly name: string) {
    super();
    this.descending = new OrderExpression(this, "DESC");
    this.desc = this.descending;
    this.ascending = this;
    this.asc = this;
  }

  render(_context?: RenderContext): string {
    return `${quoteIdentifier(this.table.name)}.${quoteIdentifier(this.name)}`;
  }

  equals(value: QueryValue): Expression {
    return new BinaryExpression(this, "=", toExpression(value));
  }

  equal(value: QueryValue): Expression {
    return this.equals(value);
  }

  notEquals(value: QueryValue): Expression {
    return new BinaryExpression(this, "<>", toExpression(value));
  }

  notEqual(value: QueryValue): Expression {
    return this.notEquals(value);
  }

  gt(value: QueryValue): Expression {
    return new BinaryExpression(this, ">", toExpression(value));
  }

  isNotNull(): Expression {
    return new UnaryExpression(this, "IS NOT NULL");
  }

  in(values: InValue): Expression {
    return new InExpression(this, values, false);
  }

  notIn(values: InValue): Expression {
    return new InExpression(this, values, true);
  }
}

function toExpression(value: QueryValue): Renderable {
  if (
    value instanceof Expression ||
    value instanceof Query ||
    value instanceof Column
  ) {
    return value;
  }
  return new ParameterExpression(value);
}

type QueryAction = "select" | "update" | "insert";
type OrderValue = string | Column | OrderExpression;

const ALLOWED_RAW_ORDER_VALUES = new Set([
  "random()",
  "is_seed desc, random()",
]);

function validateRawOrderValue(value: OrderValue): void {
  if (typeof value === "string" && !ALLOWED_RAW_ORDER_VALUES.has(value)) {
    throw new TypeError(`Raw ORDER BY value is not allowed: ${value}`);
  }
}

function validatePaginationValue(
  value: number,
  clause: "LIMIT" | "OFFSET"
): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(
      `${clause} must be a finite, safe, non-negative integer`
    );
  }
  return value;
}

export class Query implements Renderable {
  private action?: QueryAction;
  private selectValues: Renderable[] = [];
  private writeValues: Array<{ column: Column; value: QueryValue }> = [];
  private whereExpression?: Expression;
  private orderValues: OrderValue[] = [];
  private limitValue?: number;
  private offsetValue?: number;
  private returningValues: string[] = [];

  constructor(private readonly table: Table) {}

  select(...values: Renderable[]): this {
    this.action = "select";
    this.selectValues =
      values.length === 0 ? [this.table.star()] : values.flat();
    return this;
  }

  update(values: Record<string, QueryValue>): this {
    this.action = "update";
    this.writeValues = this.table.resolveWriteValues(values);
    return this;
  }

  insert(values: Record<string, QueryValue>): this {
    this.action = "insert";
    this.writeValues = this.table.resolveWriteValues(values);
    return this;
  }

  where(expression: Expression): this {
    return this.and(expression);
  }

  and(expression: Expression): this {
    this.whereExpression = this.whereExpression
      ? this.whereExpression.and(expression)
      : expression;
    return this;
  }

  or(expression: Expression): this {
    this.whereExpression = this.whereExpression
      ? this.whereExpression.or(expression)
      : expression;
    return this;
  }

  order(...values: OrderValue[]): this {
    const orderValues = values.flat();
    orderValues.forEach(validateRawOrderValue);
    this.orderValues.push(...orderValues);
    return this;
  }

  limit(value: number): this {
    this.limitValue = validatePaginationValue(value, "LIMIT");
    return this;
  }

  offset(value: number): this {
    this.offsetValue = validatePaginationValue(value, "OFFSET");
    return this;
  }

  returning(...values: string[]): this {
    this.returningValues.push(...values.flat());
    return this;
  }

  render(context: RenderContext): string {
    let text: string;
    switch (this.action) {
      case "select":
        text = this.renderSelect(context);
        break;
      case "update":
        text = this.renderUpdate(context);
        break;
      case "insert":
        text = this.renderInsert(context);
        break;
      default:
        throw new Error("Query action is required");
    }

    if (this.returningValues.length > 0) {
      text += ` RETURNING ${this.returningValues
        .map((value) => (value === "*" ? "*" : quoteIdentifier(value)))
        .join(", ")}`;
    }
    return text;
  }

  toString(): string {
    return this.render({ inlineValues: true, values: [] });
  }

  toQuery(): PostgresQuery {
    const context: RenderContext = { inlineValues: false, values: [] };
    return { text: this.render(context), values: context.values };
  }

  private renderSelect(context: RenderContext): string {
    const values = this.selectValues
      .map((value) => value.render(context))
      .join(", ");
    let text = `SELECT ${values} FROM ${quoteIdentifier(this.table.name)}`;
    text += this.renderFilters(context);
    return text;
  }

  private renderUpdate(context: RenderContext): string {
    const values = this.writeValues
      .map(
        ({ column, value }) =>
          `${quoteIdentifier(column.name)} = ${renderWriteValue(
            value,
            context
          )}`
      )
      .join(", ");
    let text = `UPDATE ${quoteIdentifier(this.table.name)} SET ${values}`;
    text += this.renderFilters(context);
    return text;
  }

  private renderInsert(context: RenderContext): string {
    const columns = this.writeValues
      .map(({ column }) => quoteIdentifier(column.name))
      .join(", ");
    const values = this.writeValues
      .map(({ value }) => renderWriteValue(value, context))
      .join(", ");
    return `INSERT INTO ${quoteIdentifier(
      this.table.name
    )} (${columns}) VALUES (${values})`;
  }

  private renderFilters(context: RenderContext): string {
    let text = "";
    if (this.whereExpression) {
      text += ` WHERE ${this.whereExpression.render(context)}`;
    }
    if (this.orderValues.length > 0) {
      text += ` ORDER BY ${this.orderValues
        .map((value) =>
          typeof value === "string" ? value : value.render(context)
        )
        .join(", ")}`;
    }
    if (this.limitValue !== undefined) {
      text += ` LIMIT ${this.limitValue}`;
    }
    if (this.offsetValue !== undefined) {
      text += ` OFFSET ${this.offsetValue}`;
    }
    return text;
  }
}

type TableDefinition = {
  name: string;
  columns: readonly string[];
};

export class Table {
  readonly columns: Column[];
  readonly [columnName: string]: unknown;

  constructor(readonly name: string, columnNames: readonly string[]) {
    this.columns = columnNames.map((name) => new Column(this, name));
    for (const column of this.columns) {
      if (!(column.name in this)) {
        Object.defineProperty(this, column.name, {
          configurable: false,
          enumerable: true,
          value: column,
          writable: false,
        });
      }
    }
  }

  select(...values: Renderable[]): Query {
    return new Query(this).select(...values);
  }

  update(values: Record<string, QueryValue>): Query {
    return new Query(this).update(values);
  }

  insert(values: Record<string, QueryValue>): Query {
    return new Query(this).insert(values);
  }

  subQuery(): Query {
    return new Query(this);
  }

  star(): StarExpression {
    return new StarExpression(this);
  }

  get(columnName: string): Column {
    const column = this.columns.find(
      (candidate) => candidate.name === columnName
    );
    if (!column) {
      throw new Error(
        `Table ${this.name} does not have a column or property named ${columnName}`
      );
    }
    return column;
  }

  resolveWriteValues(
    values: Record<string, QueryValue>
  ): Array<{ column: Column; value: QueryValue }> {
    return Object.keys(values).map((columnName) => ({
      column: this.get(columnName),
      value: values[columnName],
    }));
  }
}

export function define(definition: TableDefinition): any {
  return new Table(definition.name, definition.columns);
}

const postgresQueryBuilder = { define };

export default postgresQueryBuilder;
