import { describe, expect, jest, test } from "@jest/globals";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { spawnSync } from "node:child_process";
import ts from "typescript";
import { createFncpApplicationReadiness } from "../../src/auth/fncp-bootstrap-readiness";

const failure = "FNCP_FRESH_BOOTSTRAP_APPLICATION_NOT_READY";
function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("application registration readiness (pure callback fixtures)", () => {
  test("held helper initialization neither registers nor reports readiness", async () => {
    const helpers = deferred<object>();
    const register = jest.fn(() => undefined);
    const log = jest.fn();
    const ready = createFncpApplicationReadiness(
      helpers.promise,
      register,
      true,
      log
    );
    let complete = false;
    void ready.then(() => {
      complete = true;
    });
    await tick();
    expect(register).not.toHaveBeenCalled();
    expect(complete).toBe(false);
    const value = {};
    helpers.resolve(value);
    await ready;
    expect(register).toHaveBeenCalledTimes(1);
    expect(register).toHaveBeenCalledWith(value);
    expect(complete).toBe(true);
    expect(log).not.toHaveBeenCalled();
  });

  test("readiness waits for the last asynchronous registration acknowledgement", async () => {
    const registration = deferred<void>();
    const actions: string[] = [];
    const ready = createFncpApplicationReadiness(
      Promise.resolve({}),
      async () => {
        actions.push("routes");
        await registration.promise;
        actions.push("error-handler");
      },
      true,
      jest.fn()
    );
    let complete = false;
    void ready.then(() => {
      complete = true;
    });
    await tick();
    expect(actions).toEqual(["routes"]);
    expect(complete).toBe(false);
    registration.resolve();
    await ready;
    expect(actions).toEqual(["routes", "error-handler"]);
    expect(complete).toBe(true);
  });

  test.each([
    "helper",
    "synchronous registration",
    "asynchronous registration",
  ])(
    "fresh %s failure is constant, rejected and never logged",
    async (stage) => {
      const original = new Error("private-sensitive-sentinel");
      const log = jest.fn();
      const ready = createFncpApplicationReadiness(
        stage === "helper" ? Promise.reject(original) : Promise.resolve({}),
        () => {
          if (stage === "asynchronous registration")
            return Promise.reject(original);
          throw original;
        },
        true,
        log
      );
      await expect(ready).rejects.toThrow(failure);
      const error: any = await ready.catch((error) => error);
      expect(error).not.toBe(original);
      expect(error.cause).toBeUndefined();
      expect(String(error.stack)).not.toContain("private-sensitive-sentinel");
      expect(log).not.toHaveBeenCalled();
    }
  );

  test.each(["helper", "registration"])(
    "ordinary %s failure retains its original error and one legacy log callback",
    async (stage) => {
      const original = new Error("ordinary failure");
      const log = jest.fn();
      const ready = createFncpApplicationReadiness(
        stage === "helper" ? Promise.reject(original) : Promise.resolve({}),
        () => {
          throw original;
        },
        false,
        log
      );
      await expect(ready).rejects.toBe(original);
      expect(log).toHaveBeenCalledTimes(1);
      expect(log).toHaveBeenCalledWith(original);
    }
  );

  test("throwing ordinary logger cannot replace the readiness failure", async () => {
    const original = new Error("initialization");
    const ready = createFncpApplicationReadiness(
      Promise.reject(original),
      () => undefined,
      false,
      () => {
        throw new Error("logger");
      }
    );
    await expect(ready).rejects.toBe(original);
  });

  test("unawaited ordinary and fresh readiness rejects without an unhandled process rejection", () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, "../../src/auth/fncp-bootstrap-readiness.ts"),
      "utf8"
    );
    const compiled = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS },
    }).outputText;
    const script =
      compiled +
      `
      let unhandled = 0; let logs = 0;
      process.on('unhandledRejection', () => { unhandled++; });
      const original = new Error('ordinary fixture');
      const ordinary = exports.createFncpApplicationReadiness(Promise.reject(original), () => {}, false, () => { logs++; });
      const fresh = exports.createFncpApplicationReadiness(Promise.resolve({}), () => { throw new Error('private fixture'); }, true, () => { logs++; });
      setImmediate(() => setImmediate(async () => {
        const results = await Promise.allSettled([ordinary, fresh]);
        const correct = results[0].status === 'rejected' && results[0].reason === original &&
          results[1].status === 'rejected' && results[1].reason.message === '${failure}';
        process.stdout.write(JSON.stringify({unhandled, logs, correct}));
      }));
    `;
    // Pure source in a new Node process; no app, config, dotenv, database or file writes.
    const child = spawnSync(process.execPath, ["-e", script], {
      env: {},
      encoding: "utf8",
      timeout: 5000,
    });
    expect(child.error).toBeUndefined();
    expect(child.status).toBe(0);
    expect(child.stderr).toBe("");
    expect(JSON.parse(child.stdout)).toEqual({
      unhandled: 0,
      logs: 1,
      correct: true,
    });
  });
});

function appDeclaration() {
  const source = fs.readFileSync(
    path.resolve(__dirname, "../../app.ts"),
    "utf8"
  );
  const ast = ts.createSourceFile(
    "app.ts",
    source,
    ts.ScriptTarget.Latest,
    true
  );
  const statement = ast.statements.find(
    (node) =>
      ts.isVariableStatement(node) &&
      node.declarationList.declarations.some(
        (declaration) => declaration.name.getText(ast) === "appReady"
      )
  );
  if (!statement || !ts.isVariableStatement(statement))
    throw new Error("appReady declaration missing");
  const declaration = statement.declarationList.declarations.find(
    (node) => node.name.getText(ast) === "appReady"
  )!;
  if (!declaration.initializer || !ts.isCallExpression(declaration.initializer))
    throw new Error("readiness call missing");
  return { ast, statement, call: declaration.initializer, source };
}

function executeDeclaration(
  initialization: Promise<unknown>,
  fresh: boolean,
  app: object
) {
  const declaration = appDeclaration();
  const log = jest.fn();
  const exports: any = {};
  const compiled = ts.transpileModule(
    declaration.statement.getText(declaration.ast),
    {
      compilerOptions: { module: ts.ModuleKind.CommonJS },
    }
  ).outputText;
  // Transpile only the actual exported binding. Its callback is real source,
  // but no application imports, helpers, routes, Config or DB modules execute.
  vm.runInNewContext(compiled, {
    exports,
    helpersInitialized: initialization,
    createFncpApplicationReadiness,
    Config: { freshBootstrapLocalOnly: fresh },
    logger: { error: log },
    app,
  });
  return { ready: exports.appReady as Promise<void>, log };
}

describe("transpiled app readiness binding (no real app import)", () => {
  test("exports the helper-and-registration readiness call ending after globalErrorHandler", () => {
    const { ast, call, statement } = appDeclaration();
    expect(
      statement.modifiers?.some(
        (item) => item.kind === ts.SyntaxKind.ExportKeyword
      )
    ).toBe(true);
    expect(call.expression.getText(ast)).toBe("createFncpApplicationReadiness");
    expect(call.arguments).toHaveLength(4);
    expect(call.arguments[0].getText(ast)).toBe("helpersInitialized");
    expect(call.arguments[2].getText(ast)).toBe(
      "Config.freshBootstrapLocalOnly"
    );
    const registration = call.arguments[1];
    expect(ts.isFunctionExpression(registration)).toBe(true);
    if (!ts.isFunctionExpression(registration))
      throw new Error("registration callback missing");
    const statements = registration.body.statements;
    expect(statements[statements.length - 1].getText(ast)).toBe(
      "app.use(globalErrorHandler);"
    );
    const routeMethods: string[] = [];
    function visit(node: ts.Node) {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(ast) === "app"
      )
        routeMethods.push(node.expression.name.text);
      ts.forEachChild(node, visit);
    }
    visit(registration);
    for (const method of ["get", "post", "put", "delete"])
      expect(routeMethods).toContain(method);
  });

  test("export remains pending with helpers held, then sanitizes actual registration-callback failure", async () => {
    const initialization = deferred<unknown>();
    const entered: string[] = [];
    const { ready, log } = executeDeclaration(initialization.promise, true, {
      disable() {
        entered.push("registration");
        throw new Error("private route fixture");
      },
    });
    let settled = false;
    void ready.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      }
    );
    await tick();
    expect(settled).toBe(false);
    expect(entered).toEqual([]);
    initialization.resolve({});
    await expect(ready).rejects.toThrow(failure);
    expect(entered).toEqual(["registration"]);
    expect(log).not.toHaveBeenCalled();
  });

  test("ordinary helper rejection keeps the legacy log while exported readiness rejects", async () => {
    const original = new Error("ordinary helper fixture");
    const { ready, log } = executeDeclaration(
      Promise.reject(original),
      false,
      {}
    );
    await expect(ready).rejects.toBe(original);
    expect(log).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith("failed to init server", original);
  });
});
