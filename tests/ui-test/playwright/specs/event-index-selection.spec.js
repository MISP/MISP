// ../../event/index/selection.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, row, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const firstRowBox = (page) => main(page).locator('#tableView tbody').getByRole('checkbox').first();

test('Event index – selection kept when switching view', async ({ page }) => {
  blockedBy('Bug 7 (a ticked event loses its checkbox when switching between table and card view)');
  await page.goto('/events/index');
  await page.getByRole('button', { name: 'Table View' }).click();
  const box = firstRowBox(page);
  const id = await box.getAttribute('value');
  await box.check();

  await page.getByRole('button', { name: 'Card View' }).click();
  await expect(main(page).locator(`#cardView input[type=checkbox][value="${id}"]`)).toBeChecked();
  await page.getByRole('button', { name: 'Table View' }).click();
  await expect(main(page).locator(`#tableView input[type=checkbox][value="${id}"]`)).toBeChecked();
  await expectScreen(page.getByText(/Selected items/).first(), 'event-index-selection-switch-view.png');
});

test('Event index – selection kept when sorting', async ({ page }) => {
  blockedBy('Bug 27 (the event selection is lost when sorting the Events list)');
  await page.goto('/events/index');
  const box = firstRowBox(page);
  const id = await box.getAttribute('value');
  await box.check();
  await expect(page.getByText('Selected items: 1')).toBeVisible();

  await page.getByRole('columnheader', { name: 'ID' }).getByRole('link').click();
  await expect(page).toHaveURL(/sort:/);
  await expect(main(page).locator(`input[type=checkbox][value="${id}"]`).first()).toBeChecked();
  await expect(page.getByText('Selected items: 1')).toBeVisible();
  await expectScreen(page.getByText(/Selected items/).first(), 'event-index-selection-sort.png');
});

test('Event index – delete selected events', async ({ page, api, ts, cleanup }) => {
  const names = [`QA mass delete 1 ${ts}`, `QA mass delete 2 ${ts}`];
  for (const info of names) {
    await api.createEvent({ info });
    cleanup(() => api.deleteEventsByInfo(info));
  }

  await page.goto('/events/index');
  for (const info of names) await row(main(page), info).getByRole('checkbox').check();
  await expect(page.getByText('Selected items: 2')).toBeVisible();
  await page.getByRole('button', { name: 'Delete selected items' }).click();
  await dialog(page).getByRole('button', { name: /^Delete/ }).click();

  await expectNoErrorPage(page);
  for (const info of names) {
    await expect(row(main(page), info)).toHaveCount(0);
    expect(await api.findEvents(info)).toHaveLength(0);
  }
  await expectScreen(main(page).getByRole('heading', { name: 'Events', level: 1 }),
    'event-index-mass-delete.png');
});
