import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@tests': path.resolve(__dirname, './tests'),
      '@shared': path.resolve(__dirname, './src/shared'),
      '@infrastructure': path.resolve(__dirname, './src/infrastructure'),
      '@src': path.resolve(__dirname, './src'),
      '@applications': path.resolve(__dirname, './src/applications')
    }
  },
  test: {
    globals: true,
    environment: 'node',
    isolate: true,
    include: ['./tests/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.config.*'],
    // setupFiles: ['./tests/global-setup.ts'],
    globalSetup: './tests/global-setup.ts',
    testTimeout: 20000, // timout 20 detik untuk setiap test
    hookTimeout: 20000, // timeout 20 detik untuk setiap hook kayak beforeAll, beforeEach, afterAll dan lain lain
    clearMocks: true,
    restoreMocks: true,
    mockReset: true,
    reporters: process.env.CI ? ['verbose', 'junit', 'json'] : ['verbose'],
    outputFile: {
      junit: './test-results/junit.xml',
      json: './test-results/results.json'
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json', 'lcov'],
      reportsDirectory: './coverage',
      thresholds: {
        functions: 90, // minimal 90% fungsi harus terpanggil dalam test.
        branches: 85, // minimal 85% branch (if/else, switch, ternary) harus terpanggil.
        statements: 90, // minimal 90% pernyataan kode dieksekusi.
        lines: 90 // minimal 90% baris kode dieksekusi.
      }
    }
  }
})
