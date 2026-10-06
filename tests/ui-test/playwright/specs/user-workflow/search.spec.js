// ../../../user-workflow/search.md
const {
  test, expect, expectNoErrorPage, blockedBy, openEvent, openTab, row, pick, dialog,
} = require('../../helpers');

test.use({ role: 'userA' });

const eventRow = (page, info) => row(page.getByRole('main'), info);
const ip = (value) => ({ type: 'ip-dst', category: 'Network activity', value });

// IDs of the event rows in the order the list shows them.
async function listedIds(page) {
  const ids = await page.getByRole('main').getByRole('link', { name: /^#\d+$/ }).allInnerTexts();
  return ids.map((id) => Number(id.replace('#', '')));
}

test('Events list – search by tag', async ({ page, apiAs, api, ts, cleanup }) => {
  const tagged = `QA wf tagged ${ts}`;
  const untagged = `QA wf untagged ${ts}`;
  await apiAs('userA').createEvent({ info: tagged, tags: ['tlp:green'] });
  await apiAs('userA').createEvent({ info: untagged });
  cleanup(() => api.deleteEventsByInfo(tagged));
  cleanup(() => api.deleteEventsByInfo(untagged));

  await page.goto('/events/index');
  await page.getByRole('button', { name: 'More filters' }).click();
  await pick(page.locator('select[name=tag] + .ts-wrapper').getByRole('combobox'), 'tlp:green');
  await page.getByRole('button', { name: 'Apply filters' }).click();

  await expect(page).toHaveURL(/searchtag:/);
  await expect(eventRow(page, tagged)).toBeVisible();
  await expect(eventRow(page, untagged)).toHaveCount(0);
  await expectNoErrorPage(page);
});

test('Events list – My events', async ({ page, apiAs, api, ts, cleanup }) => {
  const mine = `QA wf mine ${ts}`;
  const other = `QA wf other ${ts}`;
  await apiAs('userA').createEvent({ info: mine });
  await apiAs('orgAdminA').createEvent({ info: other });
  cleanup(() => api.deleteEventsByInfo(mine));
  cleanup(() => api.deleteEventsByInfo(other));

  await page.goto('/events/index');
  await page.getByRole('link', { name: 'My events' }).click();

  await expect(eventRow(page, mine)).toBeVisible();
  await expect(eventRow(page, other)).toHaveCount(0);
  await expectNoErrorPage(page);
});

test('Events list – Org events', async ({ page, apiAs, api, ts, cleanup }) => {
  const orgA = `QA wf org A ${ts}`;
  const orgB = `QA wf org B ${ts}`;
  await apiAs('userA').createEvent({ info: orgA });
  await apiAs('userB').createEvent({ info: orgB, distribution: 'community' });
  cleanup(() => api.deleteEventsByInfo(orgA));
  cleanup(() => api.deleteEventsByInfo(orgB));

  await page.goto('/events/index');
  await expect(eventRow(page, orgA)).toBeVisible();
  await expect(eventRow(page, orgB)).toBeVisible();
  await page.getByRole('link', { name: 'Org events' }).click();

  await expect(eventRow(page, orgA)).toBeVisible();
  await expect(eventRow(page, orgB)).toHaveCount(0);
  await expectNoErrorPage(page);
});

test('Events list – sort by a column', async ({ page, apiAs, api, ts, cleanup }) => {
  const names = [1, 2, 3].map((n) => `QA wf sort ${n} ${ts}`);
  for (const info of names) {
    await apiAs('userA').createEvent({ info });
    cleanup(() => api.deleteEventsByInfo(info));
  }

  await page.goto('/events/index');
  const header = page.getByRole('columnheader', { name: 'ID' }).getByRole('link');
  await header.click();
  await expect(page).toHaveURL(/sort:.*direction:asc/);
  const asc = await listedIds(page);
  expect(asc).toEqual([...asc].sort((a, b) => a - b));

  await page.getByRole('columnheader', { name: 'ID' }).getByRole('link').click();
  await expect(page).toHaveURL(/sort:.*direction:desc/);
  const desc = await listedIds(page);
  expect(desc).toEqual([...desc].sort((a, b) => b - a));
  // The three new events are the newest: first on the page, newest first.
  const text = await page.getByRole('main').getByRole('table').innerText();
  expect(text.indexOf(names[2])).toBeLessThan(text.indexOf(names[0]));
  await expectNoErrorPage(page);
});

test('Export several selected events', async ({ page, apiAs, api, ts, cleanup }, testInfo) => {
  const names = [`QA wf export 1 ${ts}`, `QA wf export 2 ${ts}`];
  for (const [i, info] of names.entries()) {
    await apiAs('userA').createEvent({ info, attributes: [ip(`203.0.113.${85 + i}`)] });
    cleanup(() => api.deleteEventsByInfo(info));
  }

  await page.goto('/events/index');
  for (const info of names) await eventRow(page, info).getByRole('checkbox').check();
  await expect(page.getByText('Selected items: 2')).toBeVisible();
  await page.getByRole('button', { name: 'Export' }).click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: /^Export Events/ })).toBeVisible();
  await pick(form.getByRole('combobox', { name: /Export Format/ }), 'MISP JSON');
  const download = page.waitForEvent('download');
  await form.getByRole('button', { name: 'Export' }).click();

  const file = testInfo.outputPath('export.json');
  await (await download).saveAs(file);
  const content = require('fs').readFileSync(file, 'utf8');
  for (const [i, info] of names.entries()) {
    expect(content).toContain(info);
    expect(content).toContain(`203.0.113.${85 + i}`);
  }
});

test('Create an event from a template', async ({ page, api, cleanup }) => {
  blockedBy('Bug 9 (after creation the old event page /events/view/<id> opens)');
  const info = 'Suspicious domain — qa-wf-template.example';
  cleanup(await api.activateEventTemplate('Suspicious domain triage'));
  cleanup(() => api.deleteEventsByInfo(info));

  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  await dialog(page).getByRole('button', { name: 'Use a template' }).click();
  await dialog(page).getByRole('link', { name: /Suspicious domain triage/ }).click();
  const wizard = dialog(page);
  await wizard.getByRole('textbox', { name: /^Domain/ }).fill('qa-wf-template.example');
  await wizard.getByRole('textbox', { name: /^Date observed/ }).fill('2026-10-01T10:00:00Z');
  const next = wizard.getByRole('button', { name: 'Next', exact: true }).filter({ visible: true });
  for (let step = 2; step <= 5; step++) {
    await next.first().click();
    await expect(wizard.getByText(`Step ${step} of 5`).first()).toBeVisible();
  }
  await pick(wizard.getByRole('combobox', { name: 'Search a tag…' }), 'tlp:green');
  await wizard.getByRole('button', { name: 'Create event' }).click();

  await expect.soft(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect.poll(async () => (await api.findEvents(info)).length).toBe(1);
  const [created] = await api.findEvents(info);
  const event = await api.getEvent(created.id);
  expect(event.Attribute.map((a) => a.value)).toContain('qa-wf-template.example');
  expect(event.Tag.map((t) => t.name)).toContain('tlp:green');
});

test('Search an attribute by value', async ({ page, apiAs, api, ts, cleanup }) => {
  const known = [`QA wf known 1 ${ts}`, `QA wf known 2 ${ts}`];
  const other = `QA wf other value ${ts}`;
  for (const info of known) {
    await apiAs('userA').createEvent({ info, attributes: [ip('203.0.113.80')] });
    cleanup(() => api.deleteEventsByInfo(info));
  }
  await apiAs('userA').createEvent({ info: other, attributes: [ip('203.0.113.81')] });
  cleanup(() => api.deleteEventsByInfo(other));

  await page.goto('/attributes/index');
  const search = page.getByRole('textbox', { name: /Filter by attribute value/ });
  await search.fill('203.0.113.80');
  await search.press('Enter');

  // The list shows the event ID (#id) of each row, not its name.
  const ids = [];
  for (const info of known) ids.push((await api.findEvents(info))[0].id);
  const rows = page.getByRole('main').getByRole('row').filter({ hasText: '203.0.113.80' });
  for (const id of ids) {
    await expect(rows.filter({ has: page.getByRole('cell', { name: `#${id}`, exact: true }) }))
      .toHaveCount(1);
  }
  await expect(rows).toHaveCount(2);
  await expect(page.getByRole('main').getByText('203.0.113.81')).toHaveCount(0);
  await expectNoErrorPage(page);
});

test('Quick search of an event', async ({ page, apiAs, api, ts, cleanup }) => {
  const alpha = `QA wf quick alpha ${ts}`;
  const beta = `QA wf quick beta ${ts}`;
  await apiAs('userA').createEvent({ info: alpha });
  await apiAs('userA').createEvent({ info: beta });
  cleanup(() => api.deleteEventsByInfo(alpha));
  cleanup(() => api.deleteEventsByInfo(beta));

  await page.goto('/events/index');
  const search = page.getByRole('textbox', { name: 'Search by info, ID or UUID' });
  await search.fill(`quick alpha ${ts}`);
  await search.press('Enter');

  await expect(eventRow(page, alpha)).toBeVisible();
  await expect(eventRow(page, beta)).toHaveCount(0);
  await expect(page).toHaveURL(/\/events\/index/);
  await expectNoErrorPage(page);
});

test('Navigate through correlations', async ({ page, apiAs, api, ts, cleanup }) => {
  const first = `QA wf correl 1 ${ts}`;
  const second = `QA wf correl 2 ${ts}`;
  const domain = { type: 'domain', category: 'Network activity', value: 'qa-wf-correl.example' };
  const e1 = await apiAs('userA').createEvent({ info: first, attributes: [domain] });
  await apiAs('userA').createEvent({ info: second, attributes: [domain] });
  cleanup(() => api.deleteEventsByInfo(first));
  cleanup(() => api.deleteEventsByInfo(second));

  await openEvent(page, e1.id);
  const correlation = await openTab(page, 'Correlation');
  const link = correlation.getByRole('link', { name: new RegExp(`^${second}`) });
  await expect(link).toBeVisible();
  await link.click();

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect(page.getByRole('heading', { name: second, level: 1 })).toBeVisible();
  await expect((await openTab(page, 'Correlation'))
    .getByRole('link', { name: new RegExp(`^${first}`) })).toBeVisible();
  const attributes = await openTab(page, 'Attributes');
  // The correlation column links to the other event by its ID.
  await expect(row(attributes, 'qa-wf-correl.example')
    .getByRole('link', { name: `#${e1.id}`, exact: true })).toBeVisible();
  await expectNoErrorPage(page);
});
