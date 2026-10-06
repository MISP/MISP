const { defineConfig, devices } = require('@playwright/test');
const { MISP_URL } = require('./harness/env');

const viewport = { width: 1280, height: 1024 };

module.exports = defineConfig({
  testDir: '.',
  // Keep all generated artefacts in this folder, out of the way of git.
  outputDir: './.results',
  // The tests share one instance and some change global state (warninglists, exclusions).
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 90_000,
  expect: {
    timeout: 10_000,
    toHaveScreenshot: { maxDiffPixelRatio: 0.01, animations: 'disabled', caret: 'hide' },
  },
  snapshotPathTemplate: './__screenshots__/{testFileName}/{arg}-{platform}{ext}',
  reporter: [['list'], ['html', { outputFolder: './.report', open: 'never' }]],
  use: {
    ...devices['Desktop Chrome'],
    baseURL: MISP_URL,
    ignoreHTTPSErrors: true,
    viewport,
    colorScheme: 'light',
    locale: 'en-GB',
    timezoneId: 'UTC',
    trace: 'retain-on-failure',
    screenshot: 'on',
    video: 'retain-on-failure',
    launchOptions: { slowMo: Number(process.env.SLOWMO || 0) },
  },
  projects: [
    { name: 'setup', testMatch: /harness\/auth\.setup\.js/ },
    {
      name: 'chromium',
      testMatch: /specs\/.*\.spec\.js/,
      dependencies: ['setup'],
    },
  ],
});
