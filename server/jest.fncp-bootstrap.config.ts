/** Source-only bootstrap tests: no dotenv, database setup/reset or forced exit. */
export default {
  transform: {
    "^.+\\.(ts|tsx)$": ["ts-jest", { tsconfig: "./tsconfig.json" }],
  },
  testEnvironment: "node",
  testMatch: ["**/__tests__/unit/fncp-bootstrap-*.test.ts"],
  collectCoverage: false,
  setupFiles: [],
  setupFilesAfterEnv: [],
  forceExit: false,
  verbose: true,
  testTimeout: 15000,
};
