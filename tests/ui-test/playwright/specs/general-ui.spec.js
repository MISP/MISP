// ../../general/ui/ui.md
const {
  test, expect, blockedBy, expectScreen, dialog,
} = require('../helpers');

test.use({ role: 'orgAdminA' });

// The <header> has no height of its own: the logo link shows the MISP menu is there.
const menu = (page) => page.getByRole('banner').getByRole('link', { name: 'MISP Logo' });

// An event with many attributes and one with a proposal, then the 13 pages of the plan.
async function mainPages(api, apiAs, cleanup, ts) {
  const many = `QA ui many attributes ${ts}`;
  const proposed = `QA ui proposals ${ts}`;
  cleanup(() => api.deleteEventsByInfo(many));
  cleanup(() => api.deleteEventsByInfo(proposed));
  const attributes = Array.from({ length: 150 }, (_, i) => ({
    type: 'ip-dst', category: 'Network activity', value: `10.200.${Math.floor(i / 250)}.${i % 250}`,
  }));
  const big = await api.createEvent({ info: many, distribution: 'community', attributes });
  const withProposal = await api.createEvent({ info: proposed, distribution: 'community' });
  await apiAs('userB').proposeAttribute(withProposal.id, { type: 'ip-dst', value: '10.201.0.1' });
  return ['/events/index', `/events/view2/${big.id}`, `/events/view2/${withProposal.id}`,
    '/attributes/index', '/galaxies/index', '/tags/index', '/taxonomies/index',
    '/objectTemplates/index', '/warninglists/index', '/event_templates/index',
    '/shadow_attributes/index/all:0', '/users/view/me', '/events/add'];
}

test('Main pages – no JavaScript error', async ({ page, api, apiAs, ts, cleanup }) => {
  test.setTimeout(4 * 60_000);
  const pages = await mainPages(api, apiAs, cleanup, ts);
  const errors = [];
  let current = '';
  page.on('pageerror', (e) => errors.push(`${current}: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`${current}: ${m.text()}`); });

  for (const path of pages) {
    current = path;
    await page.goto(path);
    await expect(menu(page)).toBeVisible();
    await page.waitForLoadState('load');
  }
  expect(errors).toEqual([]);
  await expectScreen(page.getByRole('banner').getByRole('navigation'), 'general-ui-js-errors.png');
});

test('Main pages – phone width', async ({ page, api, apiAs, ts, cleanup }) => {
  test.setTimeout(4 * 60_000);
  const pages = await mainPages(api, apiAs, cleanup, ts);
  await page.setViewportSize({ width: 375, height: 812 });

  const overflowing = [];
  for (const path of pages) {
    await page.goto(path);
    await expect(menu(page)).toBeVisible();
    await page.waitForLoadState('load');
    const { scroll, width } = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth, width: document.documentElement.clientWidth,
    }));
    if (scroll > width + 1) overflowing.push(`${path} (${scroll}px for ${width}px)`);
  }
  if (overflowing.length) {
    blockedBy('New bug: at 375 px, lists with many pages (tags, taxonomies, object templates) '
      + 'scroll sideways: their pagination bar is wider than the screen');
  }
  expect(overflowing, 'pages that need a horizontal scroll').toEqual([]);
  await page.goto('/events/index');
  await expectScreen(page.getByRole('banner').getByRole('navigation'), 'general-ui-mobile.png');
});

test('Main pages – dark mode', async ({ page, api, apiAs, ts, cleanup }) => {
  test.setTimeout(4 * 60_000);
  const pages = await mainPages(api, apiAs, cleanup, ts);

  await page.goto('/events/index');
  await page.getByRole('banner').locator('.nav-link.dropdown-toggle').last().click();
  await page.locator('.dropdown-menu.show .toggle-dark-mode').click();
  await expect(page.locator('html')).toHaveAttribute('data-bs-theme', 'dark');

  const light = [];
  for (const path of pages) {
    await page.goto(path);
    await expect(menu(page)).toBeVisible();
    const theme = await page.locator('html').getAttribute('data-bs-theme');
    // Relative luminance of the page background (0 = black, 1 = white).
    const luminance = await page.evaluate(() => {
      const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\d+/g).map(Number);
      return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
    });
    if (theme !== 'dark' || luminance > 0.3) light.push(`${path} (${theme}, ${luminance.toFixed(2)})`);
  }
  expect(light, 'pages not in dark mode').toEqual([]);
  await page.goto('/events/index');
  await expectScreen(page.getByRole('banner').getByRole('navigation'), 'general-ui-dark-mode.png');
});

test.describe('as site admin', () => {
  test.use({ role: 'siteAdmin' });

  // After a refused form: still a styled MISP page (or the window), with a reason.
  async function refusedFormCheck(page, name, reason, problems) {
    await page.waitForLoadState('load');
    const styled = await page.evaluate(() => document.styleSheets.length) > 0;
    const inMisp = await menu(page).isVisible().catch(() => false);
    const shown = await page.getByText(reason).filter({ visible: true }).count();
    if (!styled || !inMisp) problems.push(`${name}: unstyled page without the menu (${page.url()})`);
    else if (!shown) problems.push(`${name}: no reason shown`);
  }

  test('Refused form – page keeps its style', async ({ page, ts, cleanup, api }) => {
    blockedBy('Bug 18 (a refused form opens an unstyled page, without CSS or menu)');
    const problems = [];

    await test.step('Allowedlist', async () => {
      const res = await page.goto('/admin/allowedlists/index');
      if (res.status() === 404 || await page.getByText(/was not found on this server/).count()) {
        test.info().annotations.push({ type: 'not applicable',
          description: 'The allowedlist was removed on develop (replaced by a warninglist)' });
      }
    });

    await test.step('Correlation exclusion – empty value', async () => {
      await page.goto('/correlation_exclusions/index');
      await page.getByRole('link', { name: 'Add correlation exclusion entry' }).click();
      await dialog(page).getByRole('button', { name: 'Add Exclusion' }).click();
      await refusedFormCheck(page, 'correlation exclusion', 'Please provide a value to exclude.', problems);
    });

    await test.step('Tag – name already used', async () => {
      await page.goto('/tags/index');
      await page.getByRole('link', { name: 'Add Tag' }).click();
      await dialog(page).locator('#TagName').fill('tlp:green');
      await dialog(page).getByRole('button', { name: 'Add Tag' }).click();
      await refusedFormCheck(page, 'tag', /already (exists|used|in use|taken)/i, problems);
    });

    await test.step('Organisation – empty form', async () => {
      await page.goto('/organisations/index');
      await page.getByRole('main').getByRole('link', { name: 'Add organisation' }).click();
      await dialog(page).getByRole('button', { name: 'Add organisation' }).click();
      await refusedFormCheck(page, 'organisation', /required|provide|cannot be empty|must/i, problems);
    });

    await test.step('Bookmark – empty form', async () => {
      await page.goto('/bookmarks/index');
      await page.getByRole('link', { name: 'Add Bookmark' }).click();
      await dialog(page).getByRole('button', { name: 'Add Bookmark' }).click();
      await refusedFormCheck(page, 'bookmark', /required|provide|cannot be empty|must/i, problems);
    });

    expect(problems).toEqual([]);
    await expectScreen(page.getByRole('banner').getByRole('navigation'), 'general-ui-refused-form.png');
  });
});

test.describe('as user of ADMIN', () => {
  test.use({ role: 'userA' });

  test('Documentation pages open', async ({ page }) => {
    blockedBy('Bug 14 (documentation pages /pages/display/… give "An Internal Error Has Occurred.")');
    await page.goto('/events/index');
    for (const path of ['/pages/display/doc/categories_and_types',
      '/pages/display/doc/md/categories_and_types']) {
      const res = await page.goto(path);
      expect(res.status(), `${path} answered`).toBeLessThan(400);
      await expect(page.getByText('An Internal Error Has Occurred.')).toHaveCount(0);
      await expect(page.getByText(/ip-dst/).first()).toBeVisible();
    }
    await expectScreen(page.getByRole('banner').getByRole('navigation'), 'general-ui-doc-pages.png');
  });
});
