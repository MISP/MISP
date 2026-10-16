#!/usr/bin/env node
//
// Re-capture the deck's screenshots from a running MISP instance.
//
//   node capture.mjs https://localhost admin@admin.test admin
//
// Needs Playwright on the machine; point PLAYWRIGHT at an install if it
// is not resolvable from here:
//
//   PLAYWRIGHT=~/some/project/node_modules/playwright/index.mjs \
//     node capture.mjs https://localhost
//
// Everything is captured in MISP's dark theme, as an element clip on a
// real page, so the deck never shows a mock-up. Values and profile
// names are the constants below; change them to match your instance.
//
// Two images the deck uses are NOT produced here, because they only
// exist while a profile is being edited: img/bench-score.png and
// img/bench-moved.png. See README.md: they come from the editor's
// bench with a value pinned and a weight changed.

import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';

const BASE = process.argv[2] || 'https://localhost';
const EMAIL = process.argv[3] || 'admin@admin.test';
const PASS = process.argv[4] || 'admin';
const OUT = process.env.OUT
    || new URL('./img', import.meta.url).pathname;

const { chromium } = await import(process.env.PLAYWRIGHT || 'playwright')
    .catch(() => {
        console.error(
            'Playwright not found. Install it, or point PLAYWRIGHT at one:\n'
            + '  PLAYWRIGHT=/path/to/node_modules/playwright/index.mjs'
            + ' node capture.mjs');
        process.exit(1);
    });

// The values the deck shows, and what each is there to demonstrate.
const VALUES = {
    contested: '8.8.8.8',
    benign: 'google.com',
    fp: '45.155.205.233',
    threat: '27304b246c7d5b4e149124d5f93c5b01',
};
const PROFILE_ID = 133;   // Incident Response & Investigation

mkdirSync(OUT, { recursive: true });

const b64 = (v) => Buffer.from(v, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_');

const browser = await chromium.launch();
const ctx = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1600, height: 1100 },
    deviceScaleFactor: 2,
});
const page = await ctx.newPage();
page.on('dialog', (d) => d.accept());

await page.goto(`${BASE}/users/login`, { waitUntil: 'domcontentloaded' });
await page.evaluate(() => localStorage.setItem('darkMode', 'true'));
await page.fill('#UserEmail', EMAIL);
await page.fill('#UserPassword', PASS);
await Promise.all([
    page.waitForURL((u) => !u.pathname.includes('/users/login'),
        { timeout: 30000 }),
    page.click('input[type="submit"], button[type="submit"]'),
]);
console.log('logged in as ' + EMAIL);

/** One element, clipped to a file. Missing or hidden is a note, not a stop. */
const shot = async (name, selector) => {
    const el = page.locator(selector).first();
    if (await el.count() === 0) { console.log('  miss  ' + name); return; }
    try {
        await el.scrollIntoViewIfNeeded({ timeout: 4000 });
        await page.waitForTimeout(350);
        await el.screenshot({ path: `${OUT}/${name}.png` });
        console.log('  shot  ' + name);
    } catch (e) {
        console.log('  skip  ' + name + ': ' + e.message.split('\n')[0]);
    }
};

/** Several adjacent blocks as one image, by the union of their boxes. */
const shotGroup = async (name, selectors) => {
    const boxes = [];
    for (const s of selectors) {
        const el = page.locator(s).first();
        if (await el.count() === 0) { continue; }
        try {
            await el.scrollIntoViewIfNeeded({ timeout: 4000 });
            boxes.push(await el.boundingBox());
        } catch (e) { /* not on this page */ }
    }
    if (!boxes.length) { console.log('  miss  ' + name); return; }
    const x = Math.min(...boxes.map((b) => b.x));
    const y = Math.min(...boxes.map((b) => b.y));
    await page.screenshot({
        path: `${OUT}/${name}.png`,
        clip: {
            x, y,
            width: Math.max(...boxes.map((b) => b.x + b.width)) - x,
            height: Math.max(...boxes.map((b) => b.y + b.height)) - y,
        },
    });
    console.log('  shot  ' + name);
};

/** The Assessment tab is lazy: open the tab, then wait for it to compute. */
const assessment = async (value) => {
    await page.goto(`${BASE}/values/view/${b64(value)}`,
        { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1200);
    await page.click('a[href="#tab-assessment"]');
    await page.waitForTimeout(5000);
};

console.log(VALUES.contested);
await assessment(VALUES.contested);
await shotGroup('hero-contested', ['.vp-vc-hero', '.vp-verdict-meta']);
await shot('lean-band', '.vp-vc-lean');
await shot('warninglist', '.vp-vc-warninglist');
await shot('ledger', '.vp-vc .table-responsive');
await shot('clock', '.vp-vc-clock');
await shot('how-reached', '.col-lg-3 .vp-aside:nth-of-type(1)');
await shot('what-would-change', '.col-lg-3 .vp-aside:nth-of-type(3)');

console.log(VALUES.benign);
await assessment(VALUES.benign);
await shotGroup('hero-benign', ['.vp-vc-hero', '.vp-verdict-meta']);

console.log(VALUES.fp);
await assessment(VALUES.fp);
await shotGroup('hero-fp', ['.vp-vc-hero', '.vp-verdict-meta']);

console.log(VALUES.threat);
await assessment(VALUES.threat);
await shotGroup('hero-threat', ['.vp-vc-hero', '.vp-verdict-meta']);

console.log('configuration');
await page.goto(`${BASE}/analyst_profiles/index`,
    { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(2500);
await shot('resolution-order', '.col-lg-2, aside');
await page.screenshot({ path: `${OUT}/profiles-index.png`, fullPage: true });
console.log('  shot  profiles-index (full page; crop to taste)');

await page.goto(`${BASE}/analyst_profiles/edit/${PROFILE_ID}`,
    { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(4000);
await page.screenshot({ path: `${OUT}/editor-signals.png` });
console.log('  shot  editor-signals');

await page.goto(
    `${BASE}/analyst_profiles/simulate/${PROFILE_ID}` +
    `?value=${b64(VALUES.contested)}`,
    { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(6000);
await shot('three-readings', '.bench-ax3');
console.log('  (this is the three cards alone; the deck\'s version'
    + ' also carries the sentence printed beneath them)');

await browser.close();
console.log('done -> ' + OUT);
