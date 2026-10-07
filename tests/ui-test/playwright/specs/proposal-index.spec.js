// ../../proposal/index/index.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, row, rowAction, openTab, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

// An event of `owner` with one attribute and a value proposal on it.
async function proposalOn(api, apiOwner, cleanup, info, ts) {
  const [from, to] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  cleanup(() => api.deleteEventsByInfo(info));
  const event = await apiOwner.createEvent({
    info, distribution: 'community', attributes: [{ type: 'ip-dst', category: 'Network activity', value: from }],
  });
  const attribute = (await api.getEvent(event.id)).Attribute[0];
  await api.proposeEdit(attribute.id, to);
  return { event, from, to };
}

test('Proposals list – my organisation\'s events', async ({ page, api, apiAs, ts, cleanup }) => {
  const own = await proposalOn(api, api, cleanup, `QA proposal own org ${ts}`, ts);
  const other = await proposalOn(api, apiAs('userB'), cleanup, `QA proposal other org ${ts}`,
    Number(ts) + 10);

  await page.goto('/shadow_attributes/index/all:0');
  const main = page.getByRole('main');
  await expect(row(main, own.to)).toBeVisible();
  await expect(row(main, other.to)).toHaveCount(0);
  for (const r of await main.locator('tbody tr').all()) await expect(r).toContainText('ADMIN');
  const ownList = await main.locator('tbody tr').allInnerTexts();
  await expectScreen(row(main, own.to), 'proposal-index-own-org.png');

  await page.goto('/shadow_attributes/index/all:1');
  await expect(row(page.getByRole('main'), own.to)).toBeVisible();
  await expect(row(page.getByRole('main'), other.to)).toBeVisible();
  expect((await page.getByRole('main').locator('tbody tr').count())).toBeGreaterThanOrEqual(ownList.length);
});

test('Proposals list – search', async ({ page, api, ts, cleanup }) => {
  const { to } = await proposalOn(api, api, cleanup, `QA proposal search ${ts}`, ts);
  await proposalOn(api, api, cleanup, `QA proposal search other ${ts}`, Number(ts) + 20);

  await page.goto('/shadow_attributes/index/all:0');
  const search = page.getByRole('main').getByRole('textbox', { name: 'Enter value to search' });
  await search.fill(to);
  await search.press('Enter');
  const rows = page.getByRole('main').locator('tbody tr');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(to);
  await expectScreen(rows.first(), 'proposal-index-search.png');
});

test('Proposals list – View Event', async ({ page, api, ts, cleanup }) => {
  const { event, from, to } = await proposalOn(api, api, cleanup, `QA proposal view ${ts}`, ts);

  await page.goto('/shadow_attributes/index/all:0');
  await rowAction(row(page.getByRole('main'), to), 'View Event');
  await expect(page).toHaveURL(new RegExp(`/events/view2/${event.id}`));
  await expect(row(await openTab(page, 'Attributes'), from)).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-index-view-event.png');
});

test('Events with proposals – actions menu', async ({ page, api, ts, cleanup }) => {
  const info = `QA proposal menu ${ts}`;
  const { event } = await proposalOn(api, api, cleanup, info, ts);

  await page.goto('/events/proposalEventIndex');
  const eventRow = page.getByRole('main').getByRole('row').filter({ hasText: info });
  await eventRow.locator('button').last().click();
  blockedBy('Bug 23 (Events with proposals list: the actions menu is empty)');
  const view = page.locator('.dropdown-menu.show').getByRole('link', { name: 'View' });
  await expect(view).toBeVisible();
  await view.click();
  await expect(page).toHaveURL(new RegExp(`/events/view2/${event.id}`));
  await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-event-index-actions.png');
});

test('Events with proposals – select rows', async ({ page, api, ts, cleanup }) => {
  const info = `QA proposal menu ${ts}`;
  await proposalOn(api, api, cleanup, info, ts);

  await page.goto('/events/proposalEventIndex');
  const eventRow = page.getByRole('main').getByRole('row').filter({ hasText: info });
  const checkbox = eventRow.locator('input[type=checkbox]');
  if (await checkbox.count()) {
    await checkbox.first().check();
    blockedBy('Bug 24 (row checkboxes do nothing on some lists)');
    await expect(page.getByText(/Selected items:\s*1/)).toBeVisible();
  }
  await expectScreen(eventRow, 'proposal-event-index-select.png');
});
