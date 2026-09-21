/** @type {import('jest').Config} */
const shared = {
  preset: "ts-jest",
  testEnvironment: "node",
  setupFiles: ["<rootDir>/tests/setup/env.ts"],
};

module.exports = {
  testTimeout: 30000,
  collectCoverageFrom: ["src/**/*.ts", "!src/server.ts", "!src/types/**"],
  coverageReporters: ["text-summary", "lcov"],
  projects: [
    {
      ...shared,
      displayName: "unit",
      testMatch: ["<rootDir>/tests/unit/**/*.test.ts"],
    },
    {
      ...shared,
      displayName: "integration",
      testMatch: ["<rootDir>/tests/integration/**/*.test.ts"],
      // Resets the test database and seeds roles once per run
      globalSetup: "<rootDir>/tests/setup/global-setup.ts",
    },
  ],
};
