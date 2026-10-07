// ../../object/relationships/relationships.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function relationshipRow(page, name) {
  await page.goto(`/object_relationships/index/quickFilter:${name}`);
  const found = page.getByRole('main').getByRole('row')
    .filter({ has: page.getByText(name, { exact: true }) }).first();
  await expect(found).toBeVisible();
  return found;
}

// The row menu offers "Remove Highlight" only on a highlighted relationship.
async function isHighlighted(page, name) {
  const found = await relationshipRow(page, name);
  await found.locator('button').last().click();
  const menu = page.locator('.dropdown-menu.show');
  await expect(menu.getByRole('link', { name: 'Edit', exact: true })).toBeVisible();
  const highlighted = await menu.getByRole('link', { name: 'Remove Highlight' }).count() > 0;
  await page.keyboard.press('Escape');
  return highlighted;
}

const relationshipId = async (found) => (await found.getByRole('link', { name: /^#\d+$/ })
  .innerText()).trim().slice(1);

// Sets the highlight through the API; returns a function putting back the state seen now.
async function setHighlight(page, api, name, state) {
  const id = await relationshipId(await relationshipRow(page, name));
  const original = await isHighlighted(page, name);
  const apply = (on) => api.post(`/object_relationships/${on ? 'massHighlight' : 'massRemoveHighlight'}/[${id}]`);
  if (state !== undefined) await apply(state);
  return () => apply(original);
}

// Ticks the rows on one page: a search would reload the list and lose the selection.
async function tick(page, names) {
  await page.goto('/object_relationships/index/limit:500');
  for (const name of names) {
    await page.getByRole('main').getByRole('row')
      .filter({ has: page.getByText(name, { exact: true }) }).first()
      .locator('input[type=checkbox]').first().check();
  }
}

const selectionAction = (page, name) => page.getByRole('main')
  .locator('a, button').filter({ visible: true }).filter({ hasText: new RegExp(`^\\s*${name}\\s*$`) });

test('Object relationships – remove highlight for selected rows', async ({ page, api, cleanup }) => {
  cleanup(await setHighlight(page, api, 'shares'));

  if (!await isHighlighted(page, 'shares')) {
    const found = await relationshipRow(page, 'shares');
    await found.locator('button').last().click();
    await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Highlight', exact: true }).click();
    await page.waitForLoadState('load');
  }
  expect(await isHighlighted(page, 'shares')).toBe(true);

  const found = await relationshipRow(page, 'shares');
  await found.locator('input[type=checkbox]').first().check();
  blockedBy('Bug 26 (Object relationships list: "Remove Highlight" is never offered for selected rows)');
  await expect(selectionAction(page, 'Remove Highlight')).toBeVisible();
  await selectionAction(page, 'Remove Highlight').click();
  await dialog(page).getByRole('button', { name: 'Confirm' }).click();
  await expect.poll(() => isHighlighted(page, 'shares')).toBe(false);
  await expectScreen(await relationshipRow(page, 'shares'), 'object-relationships-remove-highlight.png');
});

test('Object relationships – highlight selected rows', async ({ page, api, cleanup }) => {
  const names = ['derived-from', 'executes'];
  for (const name of names) cleanup(await setHighlight(page, api, name, false));

  await tick(page, names);
  await selectionAction(page, 'Highlight').first().click();
  await expect(dialog(page).getByRole('heading', { name: 'ObjectRelationship Toggle' })).toBeVisible();
  await dialog(page).getByRole('button', { name: 'Confirm' }).click();
  await page.waitForLoadState('load');
  await expectNoErrorPage(page);
  for (const name of names) await expect.poll(() => isHighlighted(page, name)).toBe(true);
  await expectScreen(await relationshipRow(page, 'executes'), 'object-relationships-highlight.png');

  await tick(page, names);
  blockedBy('Bug 26 (Object relationships list: "Remove Highlight" is never offered for selected rows)');
  await expect(selectionAction(page, 'Remove Highlight')).toBeVisible();
  await selectionAction(page, 'Remove Highlight').click();
  await dialog(page).getByRole('button', { name: 'Confirm' }).click();
  for (const name of names) await expect.poll(() => isHighlighted(page, name)).toBe(false);
});
