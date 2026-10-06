const base = require('@playwright/test');
const { storageState } = require('./lib/env');
const { adminApi, roleApi, DIST } = require('./lib/api');

const { expect } = base;

const test = base.test.extend({
  // Role of the default `page` fixture; set it with test.use({ role: '...' }).
  role: ['userA', { option: true }],

  storageState: async ({ role }, use) => use(storageState(role)),

  // Unique suffix for the names of the data a test creates ({timestamp} in the Markdown).
  ts: async ({}, use) => use(`${Date.now()}`),

  // Site admin API, for the test data (before) and the cleanup (after).
  api: async ({}, use) => {
    const api = adminApi();
    await use(api);
    await api.dispose();
  },

  // API as a given role, so the data belongs to that role's user and organisation.
  apiAs: async ({}, use) => {
    const opened = [];
    await use((role) => {
      const api = roleApi(role);
      opened.push(api);
      return api;
    });
    for (const api of opened) await api.dispose();
  },

  // Page logged in as another role, for the tests that switch user.
  pageAs: async ({ browser }, use) => {
    const contexts = [];
    await use(async (role) => {
      const context = await browser.newContext({ storageState: storageState(role) });
      contexts.push(context);
      return context.newPage();
    });
    for (const context of contexts) await context.close();
  },

  // Cleanup steps, run after the test even when it failed.
  cleanup: async ({}, use) => {
    const steps = [];
    await use((fn) => steps.push(fn));
    for (const fn of steps.reverse()) {
      await fn().catch((e) => console.warn(`cleanup: ${e.message}`));
    }
  },
});

// Marks a test with the "Known bugs on the way" of its Markdown description.
function knownBug(description) {
  test.info().annotations.push({ type: 'known bug', description });
}

// A known bug that stops the test today: Playwright reports it as an expected
// failure, and as an unexpected pass once the bug is fixed.
function blockedBy(description) {
  test.info().annotations.push({ type: 'blocked by', description });
  test.fail();
}

// "No 'An Internal Error Has Occurred.' or CSRF page is shown".
async function expectNoErrorPage(page) {
  const visible = (re) => page.getByText(re).filter({ visible: true });
  await expect(visible('An Internal Error Has Occurred.')).toHaveCount(0);
  await expect(visible('The request has been black-holed')).toHaveCount(0);
  await expect(visible('Request failed — please try again.')).toHaveCount(0);
}

// Parts of a MISP page that change on every run (ids, uuids, dates, timestamped names).
const DYNAMIC = [
  '[data-dynamic]',
  'time',
  '.timestamp',
  '.uuid',
  '[class*="uuid"]',
  '[class*="date"]',
];

/**
 * Compares one element with its committed baseline in __screenshots__/.
 * `mask` adds locators to hide on top of the always-masked dynamic parts;
 * `hide` replaces given text (e.g. the {timestamp} suffix) before the shot.
 */
async function expectScreen(locator, name, { mask = [], hide = [] } = {}) {
  const page = locator.page();
  await page.evaluate(() => document.fonts.ready);
  if (hide.length) {
    await page.evaluate((needles) => {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        for (const s of needles) {
          if (n.nodeValue.includes(s)) n.nodeValue = n.nodeValue.split(s).join('{ts}');
        }
      }
    }, hide);
  }
  await expect(locator).toHaveScreenshot(name, {
    mask: [...DYNAMIC.map((s) => page.locator(s)), ...mask],
  });
}

// --- Navigation on an event page -------------------------------------------

async function openEvent(page, id) {
  await page.goto(`/events/view2/${id}`);
  await expect(page.getByRole('tablist')).toBeVisible();
}

// Tabs show a counter ("Attributes (3)"), so match on the start of the name.
async function openTab(page, name) {
  await page.getByRole('tab', { name: new RegExp(`^${name}`) }).click();
  return page.getByRole('tabpanel').filter({ visible: true });
}

// Table row showing exactly `value` in one of its cells.
function row(scope, value) {
  return scope.getByRole('row').filter({
    has: scope.page().getByText(value, { exact: true }),
  });
}

// Waits for a background job (publish, enrichment…): reloads until `check` passes.
async function expectAfterReload(page, check, timeout = 60_000) {
  await expect(async () => {
    await page.reload();
    await check();
  }).toPass({ timeout, intervals: [2_000] });
}

// Overmind slider fields (Analysis Level, Threat Level): click the tick label.
async function chooseSlider(scope, ariaLabel, option) {
  await scope.locator('[data-choice-slider]')
    .filter({ has: scope.page().getByRole('slider', { name: ariaLabel }) })
    .locator('.ov-slider-tick', { hasText: new RegExp(`^${option}$`) })
    .click();
}

// Opens the ⋮ menu (last button) of a table row and clicks one of its entries.
async function rowAction(tableRow, name) {
  await tableRow.getByRole('button').last().click();
  await tableRow.page().locator('.dropdown-menu.show')
    .getByRole('link', { name, exact: true }).click();
}

// Tom-select field: type `search` in its combobox, then pick the option whose
// text starts with `option` (defaults to `search`).
async function pick(combobox, search, option = search) {
  // A single-value field hides its input once it has a value: click the control.
  await combobox.locator('xpath=ancestor::*[contains(@class,"ts-control")][1]').click();
  await expect(combobox).toBeFocused();
  await combobox.page().keyboard.type(search, { delay: 20 });
  const re = option instanceof RegExp ? option : new RegExp(`^${escapeRe(option)}(\\s|$)`);
  const choice = combobox.page().getByRole('option', { name: re }).filter({ visible: true }).first();
  // Hovering makes it the active option; Enter then selects it the way tom-select expects.
  await expect(async () => {
    await choice.hover();
    await expect(choice).toHaveClass(/\bactive\b/, { timeout: 1_000 });
  }).toPass();
  await combobox.press('Enter');
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// The dialog currently on top (Overmind replaces the content of one modal).
const dialog = (page) => page.getByRole('dialog').filter({ visible: true });

module.exports = {
  test, expect, knownBug, blockedBy, expectNoErrorPage, expectScreen, DIST,
  openEvent, openTab, row, rowAction, expectAfterReload, chooseSlider, pick, dialog, escapeRe,
};
