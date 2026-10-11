/** Source tests only: no dotenv, shared database setup/reset, or forced exit. */
export default {
  transform: { "^.+\\.(ts|tsx)$": ["ts-jest", { tsconfig: "./tsconfig.json" }] },
  testEnvironment: "node",
  testMatch: ["**/__tests__/unit/fncp-production-*.test.ts", "**/__tests__/unit/database-ca-tls.test.ts"],
  setupFiles: [], setupFilesAfterEnv: [], collectCoverage: false, forceExit: false,
  testTimeout: 15000,
};
