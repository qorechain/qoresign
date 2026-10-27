import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts", network: "src/network.ts" },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: false,
  clean: true,
  target: "es2022",
  splitting: true,
});
