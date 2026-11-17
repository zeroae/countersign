import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['**/dist/**', '**/node_modules/**', 'target/**'] },
  js.configs.recommended,
  { files: ['examples/demo-integrator/*.js', 'packages/companion/src/*.cjs'], languageOptions: { globals: globals.node } },
  { files: ['examples/demo-integrator/site/*.js'], languageOptions: { globals: globals.browser } },
  { files: ['packages/widget/src/**/*.js'], languageOptions: { globals: globals.browser } },
  { files: ['packages/companion/src/**/*.js'], languageOptions: { globals: globals.node } },
  { files: ['packages/companion/src/renderer.js'], languageOptions: { globals: globals.browser } },
  { files: ['**/test/**/*.js'], languageOptions: { globals: globals.node } },
];
