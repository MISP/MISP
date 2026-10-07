const base = require('@playwright/test');
const { storageState, credentials } = require('./harness/env');
const { adminApi, roleApi, DIST } = require('./harness/api');

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

// Replaces what changes on every run by fixed values, so a baseline looks like
// the real page with nothing masked: IDs, UUIDs, the {timestamp} suffix of the
// test data, today's date and the times of day. A date the test typed itself
// (2030-06-15) is kept: it is what the screenshot has to show.
async function freezeDynamicText(page, hide) {
  await page.evaluate((needles) => {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const [y, m, d] = [now.getUTCFullYear(), pad(now.getUTCMonth() + 1), pad(now.getUTCDate())];
    const longDay = new RegExp(`\\w+, (${+d} \\w+|\\w+ ${+d}),? ${y}`, 'g');
    const rules = [
      [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
        '00000000-0000-0000-0000-000000000000'],
      [/\b1\d{12}\b/g, '{ts}'],
      [/#\d+/g, '#1'],
      [new RegExp(`${y}-${m}-${d}`, 'g'), '2026-01-01'],
      [new RegExp(`${d}/${m}/${y}`, 'g'), '01/01/2026'],
      [longDay, 'Thursday, 1 January 2026'],
      [/\b\d{1,2}:\d{2}(:\d{2})?( [AP]M)?\b/g, '12:00'],
      ...needles.map((s) => [new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '{ts}']),
    ];
    const fix = (text) => rules.reduce((t, [re, to]) => t.replace(re, to), text);
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) n.nodeValue = fix(n.nodeValue);
    for (const input of document.querySelectorAll('input, textarea')) {
      if (input.value) input.value = fix(input.value);
    }
  }, hide);
}

/**
 * Compares one element (a dialog, a panel) with its committed baseline in
 * __screenshots__/. Dynamic text is replaced first (see freezeDynamicText);
 * `hide` lists extra strings to replace by "{ts}", such as the test's timestamp.
 */
async function expectScreen(locator, name, { hide = [] } = {}) {
  const page = locator.page();
  await page.evaluate(() => document.fonts.ready);
  // For a dialog, only its content: the page behind it changes with the data.
  const content = locator.locator('.modal-content').first();
  const isDialog = (await locator.getAttribute('role')) === 'dialog';
  if (isDialog) await expect(content).toBeVisible();
  // Pin the element first: it is often found by a text (a name with the test
  // timestamp) that freezeDynamicText is about to replace.
  const mark = `shot-${Date.now()}`;
  await (isDialog ? content : locator.first()).evaluate((el, id) => el.setAttribute('data-qa-shot', id), mark);
  const target = page.locator(`[data-qa-shot="${mark}"]`);
  await freezeDynamicText(page, hide);
  // No scrollbar: whether the page is long enough to show one would change the
  // width of the element by 15 px. The dialog edges are transparent: hide the
  // page behind a dialog.
  const style = 'html { scrollbar-width: none !important; } ::-webkit-scrollbar { display: none !important; }'
    + (isDialog ? ' body > :not(.modal) { visibility: hidden !important; }' : '');
  await expect(target).toHaveScreenshot(name, { style });
}

// Logs in through the login form (for a test that needs its own session).
async function loginAs(page, role) {
  const { email, password } = credentials(role);
  await page.goto('/users/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page).not.toHaveURL(/\/users\/login/);
}

// An IP only this run uses, so data left by other runs cannot interfere.
function uniqueIp(ts) {
  const n = Number(String(ts).slice(-6));
  return `10.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}`;
}

// Throwaway account for the tests that lock, log out or change the account:
// the QA accounts' stored sessions would not survive them (changing a key or
// the profile renews the session id).
const THROWAWAY_PASSWORD = 'QaThrowawayPassword-2026!';

async function throwawayUser(api, cleanup, prefix, options = {}) {
  const email = `${prefix}-${Date.now()}@admin.test`;
  cleanup(() => api.deleteUserByEmail(email));
  await api.createUser({ email, password: THROWAWAY_PASSWORD, ...options });
  return { email, password: THROWAWAY_PASSWORD };
}

async function submitLogin(page, email, password) {
  await page.goto('/users/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Login' }).click();
}

// New accounts open on the "Getting around" tour, which covers the page.
async function skipTour(page) {
  const skip = page.getByText('Skip tutorial', { exact: true });
  await skip.waitFor({ timeout: 5_000 }).catch(() => {});
  if (await skip.isVisible()) await skip.click();
  await expect(skip).toBeHidden();
}

// Logs a throwaway account in and closes its tour.
async function loginThrowaway(page, { email, password }) {
  await submitLogin(page, email, password);
  await expect(page).not.toHaveURL(/\/users\/login/);
  await skipTour(page);
}

// Opens Add Attribute on an event page and fills the form; returns the form.
// `firstSeen` / `lastSeen` use the form's own format, DD/MM/YYYY HH:MM:SS.
async function fillAttribute(page, {
  category, type, value, comment, ids, disableCorrelation, batch, firstSeen, lastSeen,
}) {
  await page.getByRole('link', { name: 'Add Attribute' }).click();
  const form = page.getByRole('dialog').filter({ visible: true });
  if (batch) await form.getByRole('checkbox', { name: /^Batch Import/ }).check();
  await pick(form.locator('#AttributeCategory + .ts-wrapper').getByRole('combobox'), category);
  // The Type list is rebuilt for the chosen category: wait for it before typing.
  await expect(form.locator(`#AttributeType option[value="${type}"]`)).toHaveCount(1);
  // Check the value really chosen (domain and domain|ip start alike) and pick again if not.
  await expect(async () => {
    if ((await form.locator('#AttributeType').inputValue()) !== type) {
      await pick(form.locator('#AttributeType + .ts-wrapper').getByRole('combobox'), type);
    }
    expect(await form.locator('#AttributeType').inputValue()).toBe(type);
  }).toPass({ timeout: 30_000 });
  await form.getByRole('textbox', { name: /Enter the indicator value/ }).fill(value);
  if (comment) await form.getByRole('textbox', { name: 'Add a contextual comment…' }).fill(comment);
  if (ids) await form.getByRole('checkbox', { name: /^For IDS/ }).check();
  if (disableCorrelation) await form.getByRole('checkbox', { name: /^Disable Correlation/ }).check();
  if (firstSeen) await form.getByRole('textbox', { name: 'First Seen (UTC)' }).fill(firstSeen);
  if (lastSeen) await form.getByRole('textbox', { name: 'Last Seen (UTC)' }).fill(lastSeen);
  return form;
}

async function submitAttribute(form) {
  await form.getByRole('button', { name: 'Add Attribute' }).click();
}

// Row of a taxonomy in /taxonomies/index (its name and description share one cell).
async function taxonomyRow(page, namespace) {
  await page.goto('/taxonomies/index');
  const box = page.getByRole('textbox', { name: 'Search by taxonomies name' });
  await box.fill(namespace);
  await box.press('Enter');
  return page.getByRole('main').getByRole('row')
    .filter({ hasText: new RegExp(`^\\s*#\\d+\\s+${namespace}\\b`) });
}

// Row menu action of a taxonomy (Enable, Disable, Require, Optional…): waits for
// the server, confirming first when MISP asks.
async function taxonomyAction(page, namespace, action) {
  const taxonomyRowLocator = await taxonomyRow(page, namespace);
  await taxonomyRowLocator.getByRole('button').last().click();
  const done = page.waitForResponse((r) => r.request().method() === 'POST'
    && /\/taxonomies\/(toggleEnable|enable|disable|toggleRequired)/.test(r.url()));
  await page.locator('.dropdown-menu.show').getByRole('link', { name: action, exact: true }).click();
  const confirm = page.getByRole('dialog').filter({ visible: true })
    .getByRole('button', { name: new RegExp(`^${action}`) });
  await Promise.race([done, confirm.waitFor()]);
  if (await confirm.isVisible()) await confirm.click();
  expect((await done).status()).toBeLessThan(400);
}

// Names of the options offered in Edit Tags (global section) for `text`.
async function offeredTags(page, eventId, text) {
  await openEvent(page, eventId);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  const box = page.getByRole('dialog').filter({ visible: true })
    .getByRole('combobox', { name: 'Search tags to add…' }).first();
  await box.click();
  await page.keyboard.type(text);
  await page.waitForTimeout(1_500);
  const names = await page.getByRole('option').filter({ visible: true }).allInnerTexts();
  await page.keyboard.press('Escape');
  return names.map((n) => n.replace(/\s+/g, ' ').trim());
}

// Blocks of the General tab of an event page, used as the final screenshot of a
// test: the summary (identifiers, distribution, publication, analysis, threat
// level), or one of the side cards by name (tags, galaxy, attachment,
// analyst-data, sightings, related, warninglist).
const eventSummary = (page) => page.getByRole('tabpanel').locator('.col-lg-9 > .card').first();
const eventCard = (page, name) => page.locator(`#${name}-card`);

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
  // A field that is still rebuilding (Type after Category) can take the focus
  // back while we type, so check the text landed and type it again if not.
  await expect(async () => {
    await combobox.locator('xpath=ancestor::*[contains(@class,"ts-control")][1]').click();
    await expect(combobox).toBeFocused({ timeout: 1_000 });
    await combobox.fill('');
    // Keep the mouse off the list: hovering an option makes it the active one.
    await combobox.page().mouse.move(0, 0);
    await combobox.page().keyboard.type(search, { delay: 20 });
    await expect(combobox).toBeFocused({ timeout: 500 });
    await expect(combobox).toHaveValue(search, { timeout: 500 });
  }).toPass({ timeout: 15_000 });
  const re = option instanceof RegExp ? option : new RegExp(`^${escapeRe(option)}(\\s|$)`);
  const page = combobox.page();
  await expect(page.getByRole('option', { name: re }).filter({ visible: true }).first()).toBeVisible();
  // Walk the list with the keyboard to the wanted option, then select it with Enter.
  const active = page.locator('[role=option].active').filter({ visible: true });
  const activeName = async () => ((await active.count())
    ? (await active.first().innerText()).replace(/\s+/g, ' ').trim() : '');
  // tom-select highlights the first match itself once the list is refreshed.
  await active.first().waitFor({ timeout: 3_000 }).catch(() => {});
  // Walk up to the top of the list first, then down to the wanted option.
  for (let i = 0; i < 50 && !re.test(await activeName()); i++) {
    const before = await activeName();
    await combobox.press('ArrowUp');
    if ((await activeName()) === before) break;
  }
  for (let i = 0; i < 50 && !re.test(await activeName()); i++) await combobox.press('ArrowDown');
  if (!re.test(await activeName())) {
    // Fallback: hovering an option makes it the active one.
    const choice = page.getByRole('option', { name: re }).filter({ visible: true }).first();
    await expect(async () => {
      await choice.hover();
      expect(await activeName()).toMatch(re);
    }).toPass({ timeout: 5_000 }).catch(() => {});
  }
  if (!re.test(await activeName())) {
    const state = await page.evaluate(() => ({
      focus: document.activeElement?.id,
      options: [...document.querySelectorAll('.ts-dropdown [role=option]')]
        .filter((o) => o.offsetParent).slice(0, 6)
        .map((o) => o.textContent.trim() + (o.classList.contains('active') ? ' (active)' : '')),
    }));
    expect(await activeName(), `option matching ${re} in the list ${JSON.stringify(state)}`).toMatch(re);
  }
  await combobox.press('Enter');
  // Leave the field, as a user moving on would: some panels redraw on blur.
  // (The combobox may be named by a placeholder that is gone once filled.)
  await combobox.page().evaluate(() => document.activeElement?.blur());
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// The dialog currently on top (Overmind replaces the content of one modal).
const dialog = (page) => page.getByRole('dialog').filter({ visible: true });

module.exports = {
  test, expect, knownBug, blockedBy, loginAs, expectNoErrorPage, expectDialogSaved, expectServerOk, expectScreen, DIST,
  addEvent, freetextImport, freetextResults, fillAttribute, submitAttribute, offeredTags, taxonomyRow, taxonomyAction,
  openEvent, openTab, row, rowAction, expectAfterReload, eventSummary, eventCard, chooseSlider, pick, dialog, escapeRe,
  throwawayUser, submitLogin, skipTour, loginThrowaway, uniqueIp,
};
