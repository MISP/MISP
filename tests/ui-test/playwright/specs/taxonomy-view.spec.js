// ../../taxonomy/view/tags.md
const {
  test, expect, expectScreen, rowAction, dialog, offeredTags, taxonomyRow, taxonomyAction,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');

test('Taxonomy – enable all tags', async ({ page, api, ts, cleanup }) => {
  cleanup(await api.keepTaxonomyState('PAP'));
  const event = await api.createEvent({ info: `QA taxonomy all tags ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await taxonomyAction(page, 'PAP', 'Enable');
  await expect.poll(async () => (await api.findTaxonomy('PAP')).enabled).toBe(true);

  const r = await taxonomyRow(page, 'PAP');
  await r.getByRole('button', { name: 'Enable all tags' }).click();
  await dialog(page).getByRole('button', { name: 'Enable all tags' }).click();
  const values = (await api.get(`/taxonomies/view/${(await api.findTaxonomy('PAP')).id}`)).entries
    ?.map((e) => e.tag) || ['PAP:CLEAR', 'PAP:GREEN', 'PAP:AMBER', 'PAP:RED'];
  const counter = (await taxonomyRow(page, 'PAP')).getByText(/\/\s*\d+/).first();
  await expect(counter.locator('..')).toContainText(new RegExp(`^\\s*${values.length}\\s*/\\s*${values.length}`));

  const offered = await offeredTags(page, event.id, 'PAP:');
  for (const value of values) expect(offered).toContain(value);
  await expectScreen(await taxonomyRow(page, 'PAP'), 'taxonomy-enable-all-tags.png');
});

test('Taxonomy – disable one tag', async ({ page, api, ts, cleanup }) => {
  const tlp = await api.findTaxonomy('tlp');
  cleanup(async () => {
    const amber = await api.findTag('tlp:amber');
    if (!amber || amber.hide_tag) await api.post(`/taxonomies/addTag/${tlp.id}`);
  });
  const event = await api.createEvent({ info: `QA taxonomy disable tag ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await page.goto(`/taxonomies/view/${tlp.id}`);
  await page.getByRole('tab', { name: /^Tags/ }).click();
  const tags = page.getByRole('tabpanel').filter({ visible: true });
  await rowAction(tags.getByRole('row').filter({ has: page.getByRole('cell', { name: 'tlp:amber', exact: true }) }), 'Disable');
  const confirm = dialog(page);
  await confirm.getByRole('button', { name: /^Disable/ }).click();
  await expect.poll(async () => (await api.findTag('tlp:amber'))?.hide_tag).toBe(true);

  const offered = await offeredTags(page, event.id, 'tlp:');
  expect(offered).not.toContain('tlp:amber');
  expect(offered).toEqual(expect.arrayContaining(['tlp:green', 'tlp:red']));

  await page.goto(`/taxonomies/view/${tlp.id}`);
  await page.getByRole('tab', { name: /^Tags/ }).click();
  const amberRow = page.getByRole('tabpanel').filter({ visible: true }).getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'tlp:amber', exact: true }) });
  await expectScreen(amberRow, 'taxonomy-disable-one-tag.png');
});
