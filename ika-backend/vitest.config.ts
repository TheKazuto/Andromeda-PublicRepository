import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    // The keystore tests run Argon2id with the production memory-hard params
    // (64 MiB); that is ~8s under v8 coverage instrumentation, well past the
    // 5s default. Fast tests are unaffected by a larger ceiling.
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/__tests__/**'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 70,
        statements: 80,
      },
    },
  },
})
