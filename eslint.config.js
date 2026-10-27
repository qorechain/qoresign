import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "docs/reference/**", "crates/**", "go/**", "swift/**", "kotlin/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
);
