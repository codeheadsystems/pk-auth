import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    typecheck: { tsconfig: "./tsconfig.json" },
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
    },
  },
});
