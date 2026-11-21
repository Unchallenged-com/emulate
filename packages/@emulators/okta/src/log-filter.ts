// The System Log's SCIM filter expressions: attribute operators, `and`, `or`, `not` and parentheses.
// https://developer.okta.com/docs/api/#filter and https://developer.okta.com/docs/reference/system-log-query/

export class LogFilterError extends Error {
  constructor(
    readonly errorCode: string,
    message: string,
  ) {
    super(message);
  }
}

type Literal = string | number | boolean | null;

type Expression =
  | { kind: "compare"; path: string; op: string; value: Literal }
  | { kind: "present"; path: string }
  | { kind: "and" | "or"; left: Expression; right: Expression }
  | { kind: "not"; operand: Expression };

const OPERATORS = new Set(["eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"]);
const EXPECTED_OPERATORS = "eq,co,sw,pr,gt,ge,lt,le";

// Paths whose objects hold free-form keys.
const OPEN_OBJECTS = [
  "actor.detailEntry",
  "target.detailEntry",
  "target.changeDetails",
  "transaction.detail",
  "debugContext.debugData",
];

const FIELDS = new Set([
  "uuid",
  "eventType",
  "legacyEventType",
  "displayMessage",
  "severity",
  "version",
  "actor.id",
  "actor.type",
  "actor.alternateId",
  "actor.displayName",
  "client.id",
  "client.ipAddress",
  "client.device",
  "client.zone",
  "client.userAgent.rawUserAgent",
  "client.userAgent.os",
  "client.userAgent.browser",
  "client.geographicalContext.city",
  "client.geographicalContext.state",
  "client.geographicalContext.country",
  "client.geographicalContext.postalCode",
  "authenticationContext.authenticationProvider",
  "authenticationContext.authenticationStep",
  "authenticationContext.credentialProvider",
  "authenticationContext.credentialType",
  "authenticationContext.externalSessionId",
  "authenticationContext.rootSessionId",
  "authenticationContext.interface",
  "authenticationContext.issuer.id",
  "authenticationContext.issuer.type",
  "securityContext.asNumber",
  "securityContext.asOrg",
  "securityContext.domain",
  "securityContext.isp",
  "securityContext.isProxy",
  "outcome.result",
  "outcome.reason",
  "target.id",
  "target.type",
  "target.alternateId",
  "target.displayName",
  "transaction.id",
  "transaction.type",
  "request.ipChain.ip",
  "request.ipChain.version",
  "request.ipChain.source",
]);

// Okta refuses `co` on these two fields with E0000031.
const NO_CONTAINS = new Set(["debugContext.debugData.url", "debugContext.debugData.requestUri"]);

function isKnownField(path: string): boolean {
  return (
    FIELDS.has(path) || OPEN_OBJECTS.some((prefix) => path.startsWith(`${prefix}.`) && path.length > prefix.length + 1)
  );
}

class Parser {
  private pos = 0;

  constructor(private readonly source: string) {}

  parse(): Expression {
    const expression = this.parseOr();
    this.skipSpace();
    if (this.pos < this.source.length) throw this.invalid();
    return expression;
  }

  private invalid(): LogFilterError {
    return new LogFilterError("E0000053", `Invalid filter '${this.source}'`);
  }

  private skipSpace(): void {
    while (this.pos < this.source.length && /\s/.test(this.source[this.pos]!)) this.pos++;
  }

  private peekWord(): string {
    this.skipSpace();
    const match = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(this.source.slice(this.pos));
    return match ? match[0] : "";
  }

  private takeKeyword(keyword: string): boolean {
    const word = this.peekWord();
    if (word.toLowerCase() !== keyword) return false;
    this.pos += word.length;
    return true;
  }

  private parseOr(): Expression {
    let left = this.parseAnd();
    while (this.takeKeyword("or")) left = { kind: "or", left, right: this.parseAnd() };
    return left;
  }

  private parseAnd(): Expression {
    let left = this.parseFactor();
    while (this.takeKeyword("and")) left = { kind: "and", left, right: this.parseFactor() };
    return left;
  }

  private parseFactor(): Expression {
    this.skipSpace();
    if (this.source[this.pos] === "(") {
      this.pos++;
      const inner = this.parseOr();
      this.skipSpace();
      if (this.source[this.pos] !== ")") throw this.invalid();
      this.pos++;
      return inner;
    }
    if (this.takeKeyword("not")) return { kind: "not", operand: this.parseFactor() };
    return this.parseComparison();
  }

  private parseComparison(): Expression {
    const path = this.peekWord();
    if (!path) throw this.invalid();
    this.pos += path.length;
    this.skipSpace();
    const opStart = this.pos;
    const op = this.peekWord();
    if (!op) throw this.invalid();
    this.pos += op.length;
    const lowered = op.toLowerCase();
    if (lowered !== "pr" && !OPERATORS.has(lowered)) {
      throw new LogFilterError(
        "E0000053",
        `Invalid filter '${this.source}': Unrecognized attribute operator '${op}' at position ${opStart}. Expected: ${EXPECTED_OPERATORS}`,
      );
    }
    if (!isKnownField(path)) throw new LogFilterError("E0000053", `field is not valid: ${path}`);
    if (lowered === "pr") return { kind: "present", path };
    if (lowered === "co" && NO_CONTAINS.has(path)) {
      throw new LogFilterError(
        "E0000031",
        `The supplied combination of operator and field is not currently supported. Operator: co, Field: ${path}`,
      );
    }
    return { kind: "compare", path, op: lowered, value: this.parseLiteral() };
  }

  private parseLiteral(): Literal {
    this.skipSpace();
    const rest = this.source.slice(this.pos);
    if (rest.startsWith('"')) {
      const match = /^"(?:[^"\\]|\\.)*"/.exec(rest);
      if (!match) throw this.invalid();
      this.pos += match[0].length;
      try {
        return JSON.parse(match[0]) as string;
      } catch {
        throw this.invalid();
      }
    }
    const word = /^[^\s()]+/.exec(rest)?.[0] ?? "";
    this.pos += word.length;
    if (word === "true") return true;
    if (word === "false") return false;
    if (word === "null") return null;
    if (word !== "" && Number.isFinite(Number(word))) return Number(word);
    throw this.invalid();
  }
}

/** Parses a filter expression, or throws a LogFilterError with Okta's error code and summary. */
export function parseLogFilter(source: string): Expression {
  return new Parser(source).parse();
}

// The values a path reaches in a record; arrays (`target`, `request.ipChain`) contribute each element.
function valuesAt(record: unknown, path: string): unknown[] {
  let current: unknown[] = [record];
  for (const key of path.split(".")) {
    const next: unknown[] = [];
    for (const value of current) {
      const items = Array.isArray(value) ? value : [value];
      for (const item of items) {
        if (item && typeof item === "object" && key in item) next.push((item as Record<string, unknown>)[key]);
      }
    }
    current = next;
  }
  return current.flatMap((value) => (Array.isArray(value) ? value : [value]));
}

function compare(actual: unknown, op: string, expected: Literal): boolean {
  if (op === "eq") return actual === expected;
  if (op === "ne") return actual !== expected;
  if (actual === null || actual === undefined || expected === null) return false;
  if (op === "co" || op === "sw" || op === "ew") {
    if (typeof actual !== "string" || typeof expected !== "string") return false;
    if (op === "co") return actual.includes(expected);
    if (op === "sw") return actual.startsWith(expected);
    return actual.endsWith(expected);
  }
  if (typeof actual !== typeof expected) return false;
  const a = actual as string | number | boolean;
  if (op === "gt") return a > expected;
  if (op === "ge") return a >= expected;
  if (op === "lt") return a < expected;
  return a <= expected;
}

function isPresent(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return false;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

export function matchesLogFilter(expression: Expression, record: unknown): boolean {
  switch (expression.kind) {
    case "and":
      return matchesLogFilter(expression.left, record) && matchesLogFilter(expression.right, record);
    case "or":
      return matchesLogFilter(expression.left, record) || matchesLogFilter(expression.right, record);
    case "not":
      return !matchesLogFilter(expression.operand, record);
    case "present":
      return valuesAt(record, expression.path).some(isPresent);
    case "compare": {
      const values = valuesAt(record, expression.path);
      if (expression.op === "ne") return values.length === 0 || values.every((v) => compare(v, "ne", expression.value));
      return values.some((value) => compare(value, expression.op, expression.value));
    }
  }
}

export type LogFilter = Expression;
