// Checks, on each list page given as argument, whether a ticked row stays ticked
// after switching to card view (Bug 2) and after sorting by a column (Bug 5).
// Usage: MISP_URL=https://localhost:8443 MISP_EMAIL=... MISP_PASSWORD=... \
//        node tests/ui-test/tools/check_list_selection.js /events/index /tags/index ...
// Needs the `playwright` npm package (set PLAYWRIGHT_PATH to its folder if it is not installed locally).
const { chromium } = require(process.env.PLAYWRIGHT_PATH || 'playwright');
const B = (process.env.MISP_URL || 'https://localhost:8443').replace(/\/$/, '');
const email = process.env.MISP_EMAIL;
const pw = process.env.MISP_PASSWORD;
if (!email || !pw) { console.error('Set MISP_EMAIL and MISP_PASSWORD'); process.exit(1); }
const pages = process.argv.slice(2);
(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
  const page = await ctx.newPage();
  await page.goto(B + '/users/login');
  await page.fill('input[name="data[User][email]"]', email);
  await page.fill('input[name="data[User][password]"]', pw);
  await Promise.all([page.waitForLoadState('load'), page.press('input[name="data[User][password]"]', 'Enter')]);
  for (const p of pages) {
    const r = { page: p };
    try {
      await page.goto(B + p, { waitUntil: 'load', timeout: 30000 });
      await page.evaluate(() => { try { localStorage.setItem('indexViewMode', 'table'); } catch (e) {} });
      await page.goto(B + p, { waitUntil: 'load', timeout: 30000 });
      await page.waitForTimeout(1500);
      const hasToggle = await page.locator('#viewCard').count();
      const boxes = page.locator('#tableView tbody input[type=checkbox]');
      r.rows = await boxes.count(); r.toggle = hasToggle > 0;
      if (!r.rows) { r.result = 'no row checkbox'; console.log(JSON.stringify(r)); continue; }
      const first = boxes.first();
      const val = await first.getAttribute('value');
      await first.check();
      if (r.toggle) {
        await page.click('#viewCard');
        await page.waitForTimeout(400);
        const cardBox = page.locator(`#cardView input[type=checkbox][value="${val}"]`);
        r.cardBoxFound = await cardBox.count() > 0;
        r.checkedInCard = r.cardBoxFound ? await cardBox.first().isChecked() : null;
        await page.click('#viewList'); await page.waitForTimeout(300);
        r.checkedBackInTable = await page.locator(`#tableView input[type=checkbox][value="${val}"]`).first().isChecked();
      }
      const sortLink = page.locator('#tableView thead a').first();
      if (await sortLink.count()) {
        await page.locator(`#tableView input[type=checkbox][value="${val}"]`).first().check();
        await Promise.all([page.waitForLoadState('load'), sortLink.click()]);
        await page.waitForTimeout(1500);
        const after = page.locator(`#tableView input[type=checkbox][value="${val}"]`);
        r.checkedAfterSort = (await after.count()) ? await after.first().isChecked() : 'row moved off page';
      } else r.checkedAfterSort = 'no sortable header';
    } catch (e) { r.error = String(e).slice(0, 120); }
    console.log(JSON.stringify(r));
  }
  await browser.close();
})();
