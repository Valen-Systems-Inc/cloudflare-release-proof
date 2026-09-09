export default [
  { ignores: ['dist/**', 'node_modules/**'] },
  {
    files: ['src/**/*.mjs', 'test/**/*.mjs', 'scripts/**/*.mjs'],
    languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
    rules: {
      'no-console': ['error', { allow: ['error'] }],
      'no-constant-binary-expression': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
    }
  }
];
