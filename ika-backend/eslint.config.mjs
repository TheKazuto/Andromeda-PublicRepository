// Lean ESLint config: correctness rules the TypeScript compiler does NOT catch
// (especially async/promise mistakes that matter in signing/billing flows),
// plus light hygiene. Stylistic/type-strictness rules are intentionally left
// out to avoid noise. Test files are covered by vitest, not linted here (the
// tsconfig excludes them from the type-checked project).
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'scripts/**', '**/*.test.ts'] },
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { '@typescript-eslint': tseslint.plugin },
    rules: {
      // High-value correctness (require type information):
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      // Hygiene:
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-unreachable': 'error',
      'no-fallthrough': 'error',
      'no-constant-condition': 'warn',
    },
  },
)
