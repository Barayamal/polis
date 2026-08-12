import base from "./jest.config";

const {
  globalSetup: _globalSetup,
  globalTeardown: _globalTeardown,
  ...baseWithoutSharedServices
} = base;

export default {
  ...baseWithoutSharedServices,
  collectCoverage: false,
  testPathIgnorePatterns: [
    ...base.testPathIgnorePatterns,
    "/__tests__/unit/app.test.ts",
  ],
};
