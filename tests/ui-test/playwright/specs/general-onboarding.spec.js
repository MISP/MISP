// ../../general/onboarding/onboarding.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, throwawayUser, submitLogin,
} = require('../helpers');
const { roleApi } = require('../harness/api');

test.use({ role: 'siteAdmin' });

const popover = (page) => page.locator('.onboarding-popover');
const STOPPED = 'Tutorial closed. Replay it from your account menu whenever you like.';

// The text of the bubble (the element itself is a dialog without .modal-content).
const bubble = (page) => popover(page).locator('.onboarding-title');

const FILTERS_BUG = /"Filters": \.dropdown-filters is not highlighted/;

// Steps already known to be broken fail the test as expected; any other problem fails it.
function expectNoProblem(problems) {
  expect(problems.filter((p) => !FILTERS_BUG.test(p)), 'tour steps that do not work').toEqual([]);
  if (problems.some((p) => FILTERS_BUG.test(p))) {
    blockedBy('New bug: the "Filters" step of the tutorial points at .dropdown-filters, which the '
      + 'Events list does not have: the step is shown with nothing highlighted, then skipped after 6 s');
    expect(problems).toEqual([]);
  }
}

// The tour as the server builds it for a role (only what the role can use).
const catalogue = (role) => roleApi(role).get('/users/onboarding.json');

async function openLauncher(page) {
  await page.goto('/events/index');
  await page.getByRole('banner').locator('.nav-link.dropdown-toggle').last().click();
  await page.locator('.dropdown-menu.show .onboarding-launch').click();
  const launcher = page.locator('.onboarding-launcher');
  await expect(launcher.getByRole('heading', { name: 'Choose where to start' })).toBeVisible();
  return launcher;
}

async function startSection(page, sections, id) {
  const launcher = await openLauncher(page);
  const section = sections.find((s) => s.id === id);
  // Only the open section shows its "Start this section" button.
  const header = launcher.getByRole('button', { name: new RegExp(`^${section.title} `) });
  if (await header.getAttribute('aria-expanded') !== 'true') await header.click();
  await launcher.locator(`.onboarding-run-section[data-section="${id}"]`).click();
}

// True once the spotlight sits on a visible element matching `anchor`.
async function spotlightOn(page, anchor) {
  return page.evaluate((selector) => {
    const spot = document.querySelector('.onboarding-spotlight');
    const box = spot && spot.getBoundingClientRect();
    if (!box || box.width < 2 || box.height < 2 || getComputedStyle(spot).display === 'none') return false;
    return [...document.querySelectorAll(selector)].some((node) => {
      const r = node.getBoundingClientRect();
      if (!r.width || !r.height) return false;
      return r.left < box.right && r.right > box.left && r.top < box.bottom && r.bottom > box.top;
    });
  }, anchor);
}

/**
 * Walks `section` step by step. Optional steps (and steps skipped where the
 * user already is) may be left out by the tour; every other step must show
 * its title and highlight its element. Returns the problems found.
 */
async function walkSection(page, section, { eventInfo } = {}) {
  const problems = [];
  let index = 0;
  while (index < section.steps.length) {
    const step = section.steps[index];
    const title = popover(page).locator('.onboarding-title');
    await expect(title).toBeVisible({ timeout: 15_000 });
    const shown = (await title.innerText()).trim();
    if (shown !== step.title) {
      if (step.optional || step.skipIf) { index += 1; continue; }
      problems.push(`${section.id} #${index} "${step.title}": the tour shows "${shown}" instead`);
      break;
    }
    await expect(popover(page).locator('.onboarding-eyebrow')).toContainText(/Step \d+ of \d+/);
    if (step.anchor) {
      const lit = await expect(async () => expect(await spotlightOn(page, step.anchor)).toBe(true))
        .toPass({ timeout: 10_000 }).then(() => true, () => false);
      if (!lit) {
        problems.push(`${section.id} #${index} "${step.title}": ${step.anchor} is not highlighted`);
        // An optional step without its element moves on by itself.
        if (step.optional && (await title.innerText()).trim() !== step.title) { index += 1; continue; }
      }
    }
    if (step.advance === 'click') {
      if (step.anchor === '#EventSubmitButton') await page.locator('#EventInfo').fill(eventInfo);
      await page.locator(step.anchor).filter({ visible: true }).first().click();
    } else {
      await popover(page).locator('.onboarding-next').click();
    }
    // Wait for the tour to leave this step (another page may load, or the tour ends).
    await expect(async () => {
      const gone = !await title.isVisible();
      expect(gone || (await title.innerText()).trim() !== step.title).toBe(true);
    }).toPass({ timeout: 15_000 }).catch(() => {});
    index += 1;
  }
  return problems;
}

async function expectFinished(page) {
  await expect(page.getByText('Tutorial complete.')).toBeVisible();
  await expect(popover(page)).toHaveCount(0);
  await expectNoErrorPage(page);
}

test.describe('as a new account', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('Tutorial – shown once to a new account', async ({ page, browser, api, cleanup }) => {
    const user = await throwawayUser(api, cleanup, 'qa-tour');

    const seen = page.waitForResponse((r) => r.url().includes('/users/onboardingSeen'));
    await submitLogin(page, user.email, user.password);
    await expect(popover(page).locator('.onboarding-title')).toHaveText('Welcome to MISP');
    await expect(popover(page).locator('.onboarding-eyebrow')).toContainText('Getting around');
    await expect(popover(page).locator('.onboarding-eyebrow')).toContainText('Step 1 of');
    await expectScreen(bubble(page), 'onboarding-first-login.png');
    expect((await seen).status()).toBeLessThan(400);
    await popover(page).locator('.onboarding-skip-all').click();
    await expect(page.getByText(STOPPED)).toBeVisible();
    await expect(popover(page)).toHaveCount(0);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    cleanup(() => context.close());
    const again = await context.newPage();
    await submitLogin(again, user.email, user.password);
    await expect(again).not.toHaveURL(/\/users\/login/);
    await again.waitForLoadState('load');
    // The tour starts on page load when it is due: give it the time it needs.
    await again.waitForTimeout(3_000);
    await expect(popover(again)).toHaveCount(0);
  });
});

test('Tutorial – sections offered to each role', async ({ pageAs }) => {
  const expected = {
    siteAdmin: ['Getting around', 'Report an incident', 'Data models', 'Sync and feeds', 'Administration'],
    orgAdminA: ['Getting around', 'Report an incident', 'Data models', 'Administration'],
    userA: ['Getting around', 'Report an incident', 'Data models'],
  };
  for (const [role, titles] of Object.entries(expected)) {
    await test.step(role, async () => {
      const page = await pageAs(role);
      const { sections } = await catalogue(role);
      expect(sections.map((s) => s.title)).toEqual(titles);
      const launcher = await openLauncher(page);
      for (const section of sections) {
        await expect(launcher.getByRole('button', { name: new RegExp(`^${section.title} .*${section.steps.length} steps`) }))
          .toBeVisible();
      }
      await expect(launcher.getByRole('button', { name: 'Start this section' })).toHaveCount(sections.length);
      if (role === 'siteAdmin') await expectScreen(launcher, 'onboarding-launcher.png');
      await launcher.getByRole('button', { name: 'Close' }).click();
      await expect(launcher).toBeHidden();
    });
  }
});

for (const role of ['siteAdmin', 'orgAdminA', 'userA']) {
  test.describe(`as ${role}`, () => {
    test.use({ role });

    test('Tutorial – Getting around', async ({ page }) => {
      const { sections } = await catalogue(role);
      await startSection(page, sections, 'general');
      const problems = await walkSection(page, sections.find((s) => s.id === 'general'));
      expectNoProblem(problems);
      await expectFinished(page);
    });
  });
}

test('Tutorial – Report an incident', async ({ page, api, ts, cleanup }) => {
  test.setTimeout(4 * 60_000);
  const eventInfo = `QA tour ${ts}`;
  cleanup(() => api.deleteEventsByInfo(eventInfo));
  const { sections } = await catalogue('siteAdmin');

  await startSection(page, sections, 'report-incident');
  const problems = await walkSection(page, sections.find((s) => s.id === 'report-incident'), { eventInfo });
  expect(await api.findEvents(eventInfo), 'the event created during the tour').toHaveLength(1);
  expectNoProblem(problems);
  await expectFinished(page);
});

test('Tutorial – Data models, Sync and Administration', async ({ page }) => {
  test.setTimeout(4 * 60_000);
  const { sections } = await catalogue('siteAdmin');
  const problems = [];
  for (const id of ['data-models', 'sync', 'administration']) {
    await startSection(page, sections, id);
    problems.push(...await walkSection(page, sections.find((s) => s.id === id)));
    await expectFinished(page);
  }
  expectNoProblem(problems);
});

test('Tutorial – Back, reload and skip', async ({ page }) => {
  const { sections } = await catalogue('siteAdmin');
  const [general, incident] = sections;
  const title = popover(page).locator('.onboarding-title');

  const launcher = await openLauncher(page);
  await launcher.getByRole('button', { name: 'Start the full tour' }).click();
  await expect(title).toHaveText(general.steps[0].title);
  await expect(popover(page).locator('.onboarding-prev')).toBeDisabled();
  await popover(page).locator('.onboarding-next').click();
  await expect(title).toHaveText(general.steps[1].title);
  await popover(page).locator('.onboarding-next').click();
  await expect(title).toHaveText(general.steps[2].title);
  await popover(page).locator('.onboarding-prev').click();
  await expect(title).toHaveText(general.steps[1].title);

  await page.reload();
  await expect(title).toHaveText(general.steps[1].title);

  await popover(page).locator('.onboarding-skip-section').click();
  await expect(title).toHaveText(incident.steps[0].title);
  await expect(popover(page).locator('.onboarding-eyebrow')).toContainText('Report an incident');
  await popover(page).locator('.onboarding-skip-part').click();
  const nextPart = incident.groups[1];
  await expect(popover(page).locator('.onboarding-eyebrow')).toContainText(nextPart.title);
  await expectScreen(bubble(page), 'onboarding-controls.png');

  await popover(page).locator('.onboarding-skip-all').click();
  await expect(page.getByText(STOPPED)).toBeVisible();
  await expect(popover(page)).toHaveCount(0);
  await page.reload();
  await expect(popover(page)).toHaveCount(0);
});
