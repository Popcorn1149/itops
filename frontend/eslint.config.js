import hooks from "eslint-plugin-react-hooks";
import react from "eslint-plugin-react";
import globals from "globals";
export default [{
  files: ["src/**/*.{js,jsx}"],
  languageOptions: { ecmaVersion: 2022, sourceType: "module", globals: globals.browser, parserOptions: { ecmaFeatures: { jsx: true } } },
  plugins: { "react-hooks": hooks, react },
  rules: { "react-hooks/rules-of-hooks": "error", "react/jsx-uses-vars": "error", "react/jsx-uses-react": "error", "no-unused-vars": ["warn", { args: "none" }], "no-undef": "error" },
}];
