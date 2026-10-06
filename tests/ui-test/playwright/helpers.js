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

// After a modal form is submitted: fails with MISP's own error message when the
// save is refused, so a report names the MISP error rather than a timeout.
async function expectDialogSaved(page) {
  const failed = page.getByText('Request failed — please try again.').filter({ visible: true });
  const open = page.getByRole('dialog').filter({ visible: true });
  await Promise.race([open.first().waitFor({ state: 'hidden' }), failed.first().waitFor()]);
  await expect(failed, 'MISP answered "Request failed — please try again."').toHaveCount(0);
  await expect(open).toHaveCount(0);
  await expectNoErrorPage(page);
}

// Clicks `target` and checks MISP's answer to the request it sends to `path`,
// so a refused action fails on the server's own status and message.
async function expectServerOk(target, path) {
  const page = target.page();
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url().includes(path) && r.request().method() !== 'GET'),
    target.click(),
  ]);
  const body = await response.text();
  expect(response.status(), `POST ${path} answered: ${body.slice(0, 200)}`).toBeLessThan(400);
  return body;
}

// Parts of a MISP page that change on every run: masked in the baselines.
function dynamicParts(page) {
  return [
    page.locator('time, .timestamp, .uuid, [data-dynamic]'),
    page.getByText(/^#\d+$/),
    page.getByText(/\b\d{4}-\d{2}-\d{2}\b/),
    page.locator('input[placeholder^="DD/MM/YYYY"]'),
  ];
}

/**
 * Compares one element (a dialog, a panel) with its committed baseline in
 * __screenshots__/. `hide` replaces given text (e.g. the {timestamp} suffix)
 * by "{ts}" first; `mask` adds locators to hide on top of dynamicParts().
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
  // For a dialog, only its content: the page behind it changes with the data.
  const content = locator.locator('.modal-content').first();
  const isDialog = (await locator.getAttribute('role')) === 'dialog';
  if (isDialog) await expect(content).toBeVisible();
  const target = isDialog ? content : locator;
  await expect(target).toHaveScreenshot(name, { mask: [...dynamicParts(page), ...mask] });
}

// Fills the Add Event form; returns once the new event page is open.
async function addEvent(page, { info, distribution = 'This community only' }) {
  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  const form = page.getByRole('dialog');
  await form.getByRole('textbox', { name: /Event Info/ }).fill(info);
  await form.getByRole('radio', { name: new RegExp(`^${distribution}`) }).check();
  return form;
}

// Populate from… > Freetext Import, up to the review window.
async function freetextImport(page, text) {
  await page.getByRole('link', { name: 'Populate from' }).click();
  const form = page.getByRole('dialog').filter({ visible: true });
  await form.getByRole('button', { name: /^Freetext Import/ }).click();
  await form.getByRole('textbox', { name: 'IOCs' }).fill(text);
  await form.getByRole('button', { name: 'Run Freetext Import' }).click();
  const review = page.getByRole('dialog').filter({ visible: true });
  await expect(review.getByRole('heading', { name: /^Review detected attributes/ })).toBeVisible();
  return review;
}

// [value, type] of each line of the Freetext Import review window.
async function freetextResults(review) {
  return review.locator('.ft-value').evaluateAll((inputs) => inputs.map((input) => {
    let box = input.parentElement;
    while (box && !box.querySelector('select.ft-type')) box = box.parentElement;
    return [input.value, box?.querySelector('select.ft-type')?.value];
  }));
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
  const page = combobox.page();
  await expect(page.getByRole('option', { name: re }).filter({ visible: true }).first()).toBeVisible();
  // Walk the list with the keyboard to the wanted option, then select it with Enter.
  const active = page.locator('[role=option].active').filter({ visible: true });
  const activeName = async () => ((await active.count())
    ? (await active.first().innerText()).replace(/\s+/g, ' ').trim() : '');
  // tom-select highlights the first match itself once the list is refreshed.
  await active.first().waitFor({ timeout: 3_000 }).catch(() => {});
  for (let i = 0; i < 50 && !re.test(await activeName()); i++) await combobox.press('ArrowDown');
  expect(await activeName(), `option matching ${re} in the list`).toMatch(re);
  await combobox.press('Enter');
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// The dialog currently on top (Overmind replaces the content of one modal).
const dialog = (page) => page.getByRole('dialog').filter({ visible: true });

module.exports = {
  test, expect, knownBug, blockedBy, expectNoErrorPage, expectDialogSaved, expectServerOk, expectScreen, DIST,
  addEvent, freetextImport, freetextResults,
  openEvent, openTab, row, rowAction, expectAfterReload, chooseSlider, pick, dialog, escapeRe,
};
