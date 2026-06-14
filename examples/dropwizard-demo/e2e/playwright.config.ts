import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.PK_DEMO_URL ?? "http://localhost:8080";
const PERSISTENCE = process.env.PK_DEMO_PERSISTENCE ?? "memory";
const externallyManaged = process.env.PK_DEMO_EXTERNAL === "1";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    channel: "chrome",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], channel: "chrome" },
    },
  ],
  webServer: externallyManaged
    ? undefined
    : {
        // Dropwizard's run task starts with `server` arg; the persistence flavor is read from
        // the `pkauth.persistence` system property (see DemoApplication#persistenceFlavor).
        // `-p ../../..` roots Gradle at the repo (the webServer runs from this config's dir, so a
        // bare `../../../gradlew` would otherwise take the e2e/ dir as the project dir and fail).
        command: `../../../gradlew -p ../../.. :examples:dropwizard-demo:run -Dpkauth.persistence=${PERSISTENCE}`,
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
        stdout: "pipe",
        stderr: "pipe",
      },
});
