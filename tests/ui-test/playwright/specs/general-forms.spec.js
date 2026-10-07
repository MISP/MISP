// ../../general/emoji/emoji.md and ../../general/limits/limits.md
const {
  test, expect, blockedBy, expectScreen, dialog, row, pick, openEvent, openTab,
  fillAttribute, submitAttribute, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

// The error page, or the line a window shows when its save answers an error.
const visibleError = (page) => page
  .getByText(/^(An Internal Error Has Occurred\.|Request failed — please try again\.)$/)
  .filter({ visible: true });

// The add forms of the two plans: each opens its form, puts `text` in the
// field under test, saves, and says how to find what it saved.
const FORMS = {
  'attribute comment': {
    async submit(page, { event, ts }, text) {
      await openEvent(page, event.id);
      const form = await fillAttribute(page, {
        category: 'Network activity', type: 'ip-dst', value: uniqueIp(ts), comment: text,
      });
      await submitAttribute(form);
    },
    saved: async (api, { event }, text) => (await api.getEvent(event.id)).Attribute
      .some((a) => a.comment === text),
  },
  'object comment': {
    async submit(page, { event, ts }, text) {
      await openEvent(page, event.id);
      await page.getByRole('link', { name: 'Add Object' }).click();
      await pick(dialog(page).getByRole('combobox', { name: /Template/ }), 'domain-ip', 'Domain-ip');
      await dialog(page).getByRole('button', { name: 'Next' }).click();
      const form = dialog(page);
      await form.getByRole('button', { name: /^Domain domain/ }).click();
      await form.locator('.attribute_row[data-object-relation="domain"] textarea.Attribute_value')
        .fill(`qa-emoji-${ts}.example`);
      await form.locator('#ObjectComment').fill(text);
      await form.getByRole('button', { name: 'Review', exact: true }).filter({ visible: true })
        .first().click();
      await form.getByRole('button', { name: 'Add Object' }).click();
    },
    saved: async (api, { event }, text) => ((await api.getEvent(event.id)).Object || [])
      .some((o) => o.comment === text),
  },
  'event report name': {
    async submit(page, { event }, text) {
      await openEvent(page, event.id);
      await page.getByRole('link', { name: 'Add Event Report' }).click();
      const form = dialog(page);
      await form.getByRole('textbox', { name: /descriptive name/ }).fill(text);
      await form.getByRole('textbox', { name: /report content in Markdown/ }).fill('QA');
      await form.getByRole('button', { name: 'Add Report' }).click();
    },
    saved: async (api, { event }, text) => ((await api.getEvent(event.id)).EventReport || [])
      .some((r) => r.name === text),
  },
  'tag collection': {
    field: 'description',
    async submit(page, { ts }, text, field) {
      await page.goto('/tag_collections/index');
      await page.getByRole('link', { name: 'Add Tag Collections' }).click();
      const form = dialog(page);
      const name = field === 'description' ? `QA collection ${ts}` : text;
      await form.getByRole('textbox', { name: 'e.g. Phishing triage set' }).fill(name);
      if (field === 'description') await form.locator('textarea').first().fill(text);
      await form.getByRole('button', { name: 'Add Collection' }).click();
    },
    cleanup: (api, { ts }) => api.deleteWhere('/tag_collections/index', 'TagCollection', 'name',
      (n) => n.includes(ts), '/tag_collections/delete'),
    saved: async (api, _, text) => (await api.listOf('/tag_collections/index', 'TagCollection'))
      .some((c) => c.name === text || c.description === text),
  },
  'custom galaxy name': {
    async submit(page, _, text) {
      await page.goto('/galaxies/index');
      await page.getByRole('link', { name: 'Add Custom Galaxy' }).click();
      const form = dialog(page);
      await form.getByRole('textbox', { name: 'Name', exact: true }).fill(text);
      await form.getByRole('textbox', { name: 'Namespace' }).fill('qa');
      await form.getByRole('button', { name: 'Add Galaxy' }).click();
    },
    cleanup: (api, _, text) => api.deleteGalaxyByName(text),
    saved: async (api, _, text) => !!(await api.findGalaxy(text)),
  },
  'galaxy cluster name': {
    async submit(page, { clusterGalaxy }, text) {
      await page.goto(`/galaxies/view/${clusterGalaxy.id}`);
      await page.getByRole('link', { name: 'Add Galaxy Cluster' }).click();
      const form = dialog(page);
      await form.getByRole('textbox', { name: 'e.g. APT28' }).fill(text);
      await form.getByRole('button', { name: 'Add Cluster' }).click();
    },
    // Listed without a search: MISP's search fails on an emoji (Bug 5).
    saved: async (api, { clusterGalaxy }, text) => (await api
      .get(`/galaxy_clusters/index/${clusterGalaxy.id}`))
      .some((c) => (c.GalaxyCluster || c).value === text),
  },
  'organisation name': {
    async submit(page, _, text) {
      await page.goto('/organisations/index');
      await page.getByRole('main').getByRole('link', { name: 'Add organisation' }).click();
      const form = dialog(page);
      await form.getByRole('textbox', { name: 'Organisation identifier' }).fill(text);
      await form.getByRole('button', { name: 'Add organisation' }).click();
    },
    cleanup: (api, _, text) => api.deleteOrgByName(text),
    saved: async (api, _, text) => (await api.get('/organisations/index/scope:all'))
      .some((o) => o.Organisation.name === text),
  },
  'sharing group name': {
    async submit(page, _, text) {
      await page.goto('/sharing_groups/index');
      await page.getByRole('link', { name: 'Add SharingGroups' }).click();
      const form = dialog(page);
      await form.getByRole('textbox', { name: 'e.g. Multinational sharing group' }).fill(text);
      await form.getByRole('textbox', { name: /e\.g\. Community1/ }).fill('QA');
      await form.getByRole('button', { name: 'Add Sharing Group' }).click();
    },
    cleanup: (api, _, text) => api.deleteSharingGroupByName(text),
    saved: async (api, _, text) => !!(await api.findSharingGroup(text)),
  },
  'warninglist': {
    field: 'description',
    async submit(page, { ts }, text, field) {
      await page.goto('/warninglists/index');
      await page.getByRole('link', { name: 'Add Warninglist' }).click();
      const form = dialog(page);
      const name = field === 'description' ? `QA warninglist ${ts}` : text;
      await form.getByRole('textbox', { name: 'e.g. Known public DNS resolvers' }).fill(name);
      await form.getByRole('textbox', { name: 'What this list contains and why a hit matters…' })
        .fill(field === 'description' ? text : 'QA test data');
      await form.getByRole('textbox', { name: /8\.8\.8\.8/ }).fill('qa-warning.example');
      await form.getByRole('button', { name: 'Add Warninglist' }).click();
    },
    cleanup: async (api, { ts }, text) => {
      await api.deleteWarninglistByName(`QA warninglist ${ts}`);
      await api.deleteWarninglistByName(text);
    },
    saved: async (api, { ts }, text) => (await api.get('/warninglists/index')).Warninglists
      .map((w) => w.Warninglist)
      .some((w) => w.name === text || (w.name === `QA warninglist ${ts}` && w.description === text)),
  },
  'feed name': {
    async submit(page, _, text) {
      await page.goto('/feeds/index');
      await page.getByRole('link', { name: 'Add Feed' }).click();
      const form = dialog(page);
      await form.locator('#FeedName').fill(text);
      await form.locator('#FeedProvider').fill('QA');
      await form.locator('#FeedUrl').fill('https://qa-feed.example/feed.json');
      await form.getByRole('button', { name: 'Add Feed' }).click();
    },
    cleanup: (api, _, text) => api.deleteWhere('/feeds/index', 'Feed', 'name', (n) => n === text,
      '/feeds/delete'),
    saved: async (api, _, text) => (await api.listOf('/feeds/index', 'Feed'))
      .some((f) => f.name === text),
  },
  'role name': {
    async submit(page, _, text) {
      await page.goto('/roles/index');
      await page.getByRole('link', { name: 'Add role' }).click();
      const form = dialog(page);
      await form.locator('#RoleName').fill(text);
      await form.getByRole('button', { name: 'Add Role' }).click();
    },
    cleanup: (api, _, text) => api.deleteWhere('/roles/index', 'Role', 'name', (n) => n === text,
      '/admin/roles/delete'),
    saved: async (api, _, text) => (await api.listOf('/roles/index', 'Role'))
      .some((r) => r.name === text),
  },
  'event blocklist comment': {
    async submit(page, { blockedUuid }, text) {
      await page.goto('/eventBlocklists/index');
      await page.getByRole('link', { name: 'Add event blocklist' }).click();
      const form = dialog(page);
      await form.locator('#BlocklistUuids').fill(blockedUuid);
      await form.locator('#EventBlocklistComment').fill(text);
      await form.getByRole('button', { name: 'Add to Blocklist' }).click();
    },
    cleanup: (api, { blockedUuid }) => api.deleteWhere('/eventBlocklists/index', 'EventBlocklist',
      'event_uuid', (u) => u === blockedUuid, '/eventBlocklists/delete'),
    saved: async (api, _, text) => (await api.listOf('/eventBlocklists/index', 'EventBlocklist'))
      .some((b) => b.comment === text),
  },
  'object relationship name': {
    async submit(page, _, text) {
      await page.goto('/object_relationships/index');
      await page.getByRole('link', { name: 'Add Object Relationship' }).click();
      const form = dialog(page);
      await form.locator('#ObjectRelationshipName').fill(text);
      await form.getByRole('button', { name: 'Add Relationship' }).click();
    },
    // The JSON list of object relationships is missing: checked in the page instead.
    saved: null,
    async savedInPage(page, api, cleanup, prefix) {
      await page.goto(`/object_relationships/index/quickFilter:${encodeURIComponent(prefix)}`);
      const ids = (await page.getByRole('main').locator('tbody')
        .getByRole('link', { name: /^#\d+$/ }).allInnerTexts()).map((t) => t.trim().slice(1));
      for (const id of ids) cleanup(() => api.post(`/object_relationships/delete/${id}`));
      return ids.length > 0;
    },
  },
};

async function context(api, cleanup, ts, info) {
  cleanup(() => api.deleteEventsByInfo(info));
  const event = await api.createEvent({ info });
  const clusterGalaxy = await api.createGalaxy(`QA cluster galaxy ${ts}`);
  cleanup(() => api.deleteGalaxyByName(clusterGalaxy.name));
  const blockedUuid = `00000000-0000-4000-8000-${String(ts).slice(-12).padStart(12, '0')}`;
  return { event, clusterGalaxy, blockedUuid, ts };
}

// Fills each form in turn; soft checks so every form is tried and reported.
async function tryForms(page, api, cleanup, ctx, names, textFor, check) {
  for (const name of names) {
    const form = FORMS[name];
    const text = textFor(name);
    if (form.cleanup) cleanup(() => form.cleanup(api, ctx, text));
    await test.step(name, async () => {
      await form.submit(page, ctx, text, form.field);
      // Let the save finish: the window closes, or an error replaces it.
      await Promise.race([
        dialog(page).first().waitFor({ state: 'hidden', timeout: 15_000 }),
        visibleError(page).first().waitFor({ timeout: 15_000 }),
      ]).catch(() => {});
      await page.waitForLoadState('load');
      await check(name, form, text);
    }).catch((e) => { expect.soft(e.message, `${name}: step failed`).toBe(''); });
  }
}

test('Emoji in every text field', async ({ page, api, ts, cleanup }) => {
  test.setTimeout(6 * 60_000);
  blockedBy('Bug 5 (an emoji in many text fields gives "An Internal Error Has Occurred.")');
  const info = `QA emoji 🚀 ${ts}`;
  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  await dialog(page).getByRole('textbox', { name: /Event Info/ }).fill(info);
  await dialog(page).getByRole('button', { name: 'Create Event Entry' }).click();
  cleanup(() => api.deleteEventsByInfo(info));
  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  const [created] = await api.findEvents(info);
  const ctx = await context(api, cleanup, ts, `QA emoji support ${ts}`);
  ctx.event = { id: created.id };

  const failed = [];
  const names = ['attribute comment', 'object comment', 'custom galaxy name',
    'galaxy cluster name', 'organisation name', 'sharing group name', 'tag collection',
    'feed name', 'warninglist', 'role name', 'event blocklist comment'];
  await tryForms(page, api, cleanup, ctx, names, (name) => `QA ${name} 🚀 ${ts}`,
    async (name, form, text) => {
      const error = await visibleError(page).count();
      const saved = await form.saved(api, ctx, text);
      if (error || !saved) failed.push(`${name}${error ? ' (internal error)' : ' (not saved)'}`);
      expect.soft(error, `${name}: internal error`).toBe(0);
      expect.soft(saved, `${name}: saved with its emoji`).toBe(true);
    });
  expect(failed, 'forms that do not take an emoji').toEqual([]);
  await openEvent(page, created.id);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'general-emoji-fields.png');
});

test('Too long text in add forms', async ({ page, api, ts, cleanup }) => {
  test.setTimeout(8 * 60_000);
  blockedBy('Bug 17 (a too long text gives "An Internal Error Has Occurred." instead of a message)');
  const ctx = await context(api, cleanup, ts, `QA long text ${ts}`);
  const long = (name) => `QA long ${name} ${ts} ${'Q'.repeat(70_000)}`;

  const failed = [];
  const names = ['attribute comment', 'object comment', 'event report name', 'tag collection',
    'custom galaxy name', 'organisation name', 'sharing group name', 'warninglist', 'feed name',
    'role name', 'event blocklist comment', 'object relationship name'];
  await tryForms(page, api, cleanup, ctx, names, long, async (name, form, text) => {
    const error = await visibleError(page).count();
    const message = await page.getByText(/too long|maximum length|at most \d+ characters/i)
      .filter({ visible: true }).count();
    const saved = form.saved ? await form.saved(api, ctx, text)
      : await form.savedInPage(page, api, cleanup, `QA long ${name} ${ts}`);
    if (error || !message || saved) {
      failed.push(`${name}${error ? ' (internal error)' : ''}${saved ? ' (saved)' : ''}`
        + `${!message ? ' (no message)' : ''}`);
    }
    expect.soft(error, `${name}: internal error`).toBe(0);
    expect.soft(saved, `${name}: the too long text is not saved`).toBe(false);
    expect.soft(message, `${name}: a message about the length`).toBeGreaterThan(0);
  });
  expect(failed, 'forms without a length message').toEqual([]);
});

test('Correlation exclusion – too long value', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 17 (a 70,000-character exclusion value gives "An Internal Error Has Occurred.")');
  const value = `QA long exclusion ${ts} ${'Q'.repeat(70_000)}`;
  cleanup(() => api.deleteCorrelationExclusion(value));

  await page.goto('/correlation_exclusions/index');
  await page.getByRole('link', { name: 'Add correlation exclusion entry' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: '8.8.8.8' }).fill(value);
  await form.getByRole('button', { name: 'Add Exclusion' }).click();
  await page.waitForLoadState('load');
  await expect(visibleError(page)).toHaveCount(0);
  expect((await api.correlationExclusions()).some((e) => e.value.startsWith(`QA long exclusion ${ts}`)))
    .toBe(false);
  await expect(page.getByText(/too long|maximum length|at most \d+ characters/i).first()).toBeVisible();
  await expectScreen(form, 'general-limits-correlation-exclusion.png');
});

test('Too long search', async ({ page }) => {
  blockedBy('Bug 17 (a 20,000-character search gets "414 Request-URI Too Large")');
  await page.goto('/events/index');
  const search = page.getByRole('textbox', { name: 'Search by info, ID or UUID' });
  await search.fill('Q'.repeat(20_000));
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url().includes('/events/index') && r.request().method() === 'GET',
      { timeout: 15_000 }).catch(() => null),
    search.press('Enter'),
  ]);
  if (response) expect(response.status(), 'search request answered').not.toBe(414);
  await expect(page.getByText(/414|Request-URI Too Large/)).toHaveCount(0);
  const limited = (await search.inputValue().catch(() => '')).length < 20_000;
  const message = await page.getByText(/too long|maximum length/i).filter({ visible: true }).count();
  expect(limited || message > 0, 'the search is limited or a message is shown').toBe(true);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'general-limits-search.png');
});

