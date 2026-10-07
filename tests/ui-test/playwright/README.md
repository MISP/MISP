# MISP UI end-to-end tests (Playwright)

Browser tests that replay the Markdown test plans of `../use-case/` and `../user-workflow/`
on a real MISP instance (Overmind theme). Each spec follows its Markdown test step by step:
same roles, same test data, same **Expected** checks. The goal is to **catch regressions in
the analyst workflows** — if a change breaks a form, a button or a page, a test fails and
shows you the trace, the screenshot and the video of the failure.

> Side benefit: a few specs also compare key screens with committed baseline images, so
> an unintended visual change is caught too (see [Visual baselines](#visual-baselines)).

## Quick start

```bash
cd tests/ui-test/playwright
npm install
cp .env.example .env         # then fill in the passwords and API keys

npm run test:e2e             # run every spec
npm run test:e2e:use-case    # only the analyst scenarios (use-case/)
npm run test:e2e:workflow    # only the user workflows (user-workflow/)
npm run test:e2e:event       # only the event plans (event/)
npm run test:e2e:update      # re-generate the visual baselines
npm run test:e2e:ui          # interactive Playwright UI runner
npm run test:e2e:report      # open the HTML report (trace / screenshot / diff gallery)
```

Unlike a front-end project, there is no dev server to boot: the tests need a **running
MISP instance** (default `https://localhost:8443`, set `MISP_URL` in `.env`) with the
test accounts of `../README.md` ("Test organisations and accounts").

## Watching the tests run

Two ways to see what a test does in real time (both need a desktop/display):

```bash
npm run test:e2e:ui                  # interactive runner — best for inspecting
SLOWMO=600 npm run test:e2e:headed   # watch a real browser drive MISP live
```

- **UI mode** (`:ui`) opens a runner where you pick a test, watch it execute, then
  time-travel through every action with before/after DOM snapshots, console and network.
  It re-runs automatically when you edit a spec (watch mode).
- **Headed mode** (`:headed`) opens an actual Chromium window and performs the actions in
  front of you. Set `SLOWMO=<ms>` to slow each action down enough to follow.
- After any run, `npm run test:e2e:report` opens the HTML report; a failed test keeps its
  trace, screenshot and video.

## How it works

```
tests/ui-test/playwright/
├─ harness/
│  ├─ env.js            # .env loading, roles, paths
│  ├─ api.js            # MISP API client: test data (before) and cleanup (after)
│  └─ auth.setup.js     # logs in once per role, sessions saved in .auth/
├─ specs/               # one spec per Markdown file, named after its path:
│                       #   use-case-01-phishing-triage, user-workflow-creation, event-add-fields…
├─ helpers.js           # fixtures (role pages, API, cleanup) + assertion and screenshot helpers
├─ __screenshots__/     # committed baseline PNGs, one folder per spec
├─ .results/            # traces, videos, actual/diff images of the last run (not committed)
└─ .report/             # HTML report of the last run (not committed)
```

Every test is built the same way as its Markdown test, and **ends with a screenshot of its
final state** (`expectScreen`), compared with its baseline: the test passes only if the
functional checks pass *and* the screen looks like the committed baseline.

| Markdown                    | Spec                                                                  |
| --------------------------- | --------------------------------------------------------------------- |
| **Role:**                   | `test.use({ role: 'orgAdminA' })`; a second role with `pageAs('userB')` |
| `{timestamp}`               | the `ts` fixture (unique per test)                                     |
| **Test data (before):**     | created through the API, as the right role: `apiAs('orgAdminA').createEvent(...)` |
| **Cleanup (after):**        | `cleanup(() => api.deleteEventsByInfo(name))` — runs even if the test fails |
| **Known bugs on the way:**  | `knownBug('Bug 4 …')` — shown as an annotation in the report           |
| numbered steps / phases     | `test.step('Phase 1 – …')`, one Playwright action per Markdown step    |
| **Expected:**               | `expect(...)` assertions, then the final screenshot (`expectScreen`)   |

Elements are found the way the Markdown names them — by role and exact label
(`getByRole('button', { name: 'Add Event' })`) — never by CSS position. MISP pages keep
polling and never become idle, so the tests always wait for a precise text or element,
never for a delay or `networkidle`.

The roles (`siteAdmin`, `userA`, `orgAdminA`, `userB`, `orgAdminB`) log in once in the
`setup` project; every test reuses the saved session (`.auth/`, never committed).

### Why it's deterministic

| Source of variance          | How it's pinned                                                      |
| --------------------------- | -------------------------------------------------------------------- |
| Existing data on the instance | each test creates its own data with a unique `{timestamp}` name and finds it by name, never by ID |
| Leftover data               | cleanup steps run after every test, even a failed one                 |
| Two tests touching global state | single worker, tests run one after the other                      |
| Colour scheme               | `colorScheme: 'light'`                                                |
| Dates and time zone         | `timezoneId: 'UTC'`, `locale: 'en-GB'`                                 |
| Viewport size               | pinned to 1280×1024 in `playwright.config.js` (tall enough for the Add Event window) |
| Web fonts                   | `await document.fonts.ready` before a screenshot                      |
| Browser engine              | Chromium only                                                         |
| IDs, UUIDs, dates, timestamped names | masked or replaced by `expectScreen()` before a screenshot   |
| Sub-pixel anti-aliasing     | `maxDiffPixelRatio: 0.01` tolerance in the screenshot config          |

## Coverage

A test stopped by a known MISP bug is marked with `blockedBy('Bug N …')`: Playwright counts it as
an *expected failure*, stops at the bug, and reports an *unexpected pass* once the bug is fixed —
the signal to remove the marker. The check that fails is always MISP's own answer (the HTTP
status and message of the refused request, or the error shown in the UI), never a timeout.

| Spec                                   | What it checks | Stopped today by |
| -------------------------------------- | -------------- | ---------------- |
| `use-case-01-phishing-triage`          | Create an event, email object, freetext import, tag + galaxy, publish | Bug 4 (object add) |
| `use-case-02-campaign-correlation`     | Correlation with an earlier wave, extends, sighting | Bug 3 (sighting) |
| `use-case-03-partner-sharing`          | Sharing group, partner sighting + proposal, accept | Bug 3, proposals black-holed |
| `use-case-04-attachment-analysis`      | Malware sample upload, hashes, protected zip download, `domain-ip` object | Bug 4 (object add) |
| `use-case-05-false-positive`           | Warninglist hit, false positive sighting, IDS off, correlation exclusion | Bug 3 (false positive) |
| `use-case-06-defence-export`           | Text and CSV export without the non-IDS value | — |
| `use-case-07-report-attribution`       | Event report, threat actor cluster, note + opinion | — |
| `use-case-08-close-incident`           | Soft delete / restore, analysis change, republish, history | — |
| `user-workflow-creation`               | Event, object, attribute, tags, report, attachment, populate, enrich, publish, batch, restore | Bug 4 (object add/edit), Bug 10 (report); Enrich skipped without an enabled module |
| `user-workflow-search`                 | Events list filters, sort, export of a selection, template, attribute search, quick search, correlations | Bug 9 (template) |
| `user-workflow-collaboration`          | Proposals between organisations: accept, discard, new attribute | proposals black-holed; no "propose attribute" button |
| `event-add-fields`                     | Add Event: dates, defaults, every field, distribution levels, extends, HTML and line breaks in Event Info | — |
| `event-add-validation`                 | Add Event refusals: empty or blank Event Info, invalid date, unknown Extends ID, Event Info too long | Bug 8 (too long); unknown Extends ID loses the form |
| `event-edit`                           | Edit Event: fields, future date, too long Info, extends itself, two tabs, deleted meanwhile, logged out, published event, empty Info | Bug 8; an event can extend itself; two tabs: the last save silently wins |
| `event-index-filters`                  | Events list: galaxy, tag, reversed dates, special characters, page out of range, single match, combined filters, filter kept on page 2 | Bug 1 (galaxy filter) |
| `event-index-selection`                | Selection kept when switching view or sorting, delete selected events | Bug 7, Bug 27 |
| `event-roles-permissions`              | Visibility and edit/publish rights per role and organisation | — |
| `event-view-actions`                   | Publish / unpublish, publish an empty event, delete, delete an extended event, tags and clusters, unknown event, open by UUID, extends cycle | Bug 9 (unpublish) |
| `event-view-performance`               | An event with 2,000 attributes: shown in less than 5 s, next page, search | — |
| `attribute-add`                        | Add Attribute: valid values, refused values (IP, md5, port, duplicates), normalisation, IDN, First/Last Seen, types per category, published event, warninglist, no correlation, emoji | refused values lose the form and the reason; Bug 5 (emoji) |
| `attribute-batch`                      | Batch import: valid, partly invalid, blank lines, duplicates | — |
| `attribute-attachment`                 | Attachment upload and download, malware sample (hashes, encrypted zip), upload without a file | upload without a file shows no message |
| `attribute-view`                       | Edit (invalid value, IDS), soft delete / restore, delete removes the correlation, filter, correlation icon, selection | Bug 11 (icon not updated) |
| `attribute-index-search`               | Attributes list: by value, by type, special characters | — |
| `tag-index`                            | Add (custom, empty, duplicate, too long, colour), search, rename and delete used tags, hidden, not exportable, favourites | Bug 19, Bug 20; a duplicate is refused with no message; an invalid colour is silently replaced |
| `tag-local`                            | Local tags, local-only tags (global, local, several events), filter by a local tag | a local-only tag is never offered; no tag action on several events |
| `tag-collections`                      | Tag collections: empty name, tags and cluster, emoji, apply, exclusive tags, download, delete | Bug 5; exclusive taxonomies are not enforced |
| `tag-roles-permissions`                | Global and local tags on another organisation's event, tag restricted to an organisation, User role | no way to add a local tag on another organisation's event |
| `galaxy-index`                         | Custom galaxy (empty name, create, kill chain), disable a galaxy, delete a used galaxy, import (invalid JSON, no cluster) | clusters of a disabled galaxy are still offered; unpublished clusters are not offered (to confirm) |
| `galaxy-clusters`                      | Clusters: empty name, elements, fork, rename and soft delete while used, hard delete and re-import, publish | deleting a cluster is black-holed; unpublished clusters are not offered (to confirm) |
| `galaxy-relations`                     | Relations between clusters (by UUID): add, without type, to itself, target deleted | deleting a cluster is black-holed |
| `taxonomy-index`                       | Enable / disable, required taxonomy and publish (with / without notification, tagged), disabled taxonomy on an event, update, disabled taxonomy and galaxy everywhere | re-enabled taxonomy tags stay hidden (to confirm); clusters of a disabled galaxy still offered |
| `taxonomy-view`                        | Enable all tags, disable one tag | — |
| `taxonomy-exclusive`                   | Two tlp values on one event, replace a value, event and attribute | exclusive taxonomies are not enforced |
| `event-report-add`                     | Reports: Markdown, HTML and scripts shown as text, HTML and emoji in the name, 3 MB report, attribute reference, delete and restore, page after creating | Bug 10; deleted reports cannot be shown or restored |
| `event-report-extract`                 | Extract indicators, reviewed replacements, import from URL off, PDF, old rendered view | only AI extraction is offered; viewRendered gives an internal error; PDF skipped without the convert_markdown_to_pdf module |
| `import-export-freetext`               | Freetext: defanged, punctuation and duplicates, types, nothing found, bulk changes, proposals | — |
| `import-export-import`                 | Import Event: MISP JSON, event already present, invalid text, take ownership, STIX 2 | invalid text does nothing (no message); no "Take ownership" option |
| `import-export-export`                 | Download as MISP JSON, CSV formulas, STIX 2; several events; cached exports | Bug 2 |
| `sharing-group-index`                  | Create with two organisations, emoji in the name, delete while used, member cannot edit | Bug 5; deleting a used sharing group gives no reason |
| `sharing-group-visibility`             | Event in a sharing group seen by a non-member and a member, non-member cannot use it, organisation removed | — |
| `warninglist-index`                    | Default and Enabled filters of the Warninglists list | Bug 21 |
| `correlation-correlations`             | Same value in two events, exclusion and clean up, same exclusion twice, empty exclusion, top correlations | Bug 18 |
| `analyst-data-notes`                   | Note without text, edited to an empty text, with text, four nested levels, counters with nested notes and opinions | Bug 12; Bug 16 |

## Writing a new test

```js
const { test, expect, expectNoErrorPage } = require('../../helpers');

test.use({ role: 'userA' });

test('Add attribute', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf attribute ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await page.goto(`/events/view2/${event.id}`);
  await page.getByRole('button', { name: 'Add attribute' }).click();
  // ... one action per Markdown step ...
  await expect(page.getByRole('row', { name: /qa-wf-attribute\.example/ })).toBeVisible();
  await expectNoErrorPage(page);
});
```

- **Write the Markdown test first** (`../README.md`, or the `misp-test-plan` skill), then
  the spec: the test name is the Markdown `###` title, so a failure points to its plan.
- **Data before / after** goes through `harness/api.js`; add a method there rather than
  calling the API from a spec.
- **A known bug** that stops the test: `blockedBy('Bug N …')`, and check the server's answer to
  the refused action with `expectServerOk(button, '/controller/action/')` or
  `expectDialogSaved(page)`, so the report names the MISP error.
- **Sessions last 60 minutes** on a default instance: run with the `setup` project (the default)
  rather than `--no-deps`, or the stored logins may have expired.
- **Shared helpers** (fixtures, assertions) go in `helpers.js`.

## Screenshots

- **The final screenshot decides, with the checks, whether a test passes.** Each test ends with
  `expectScreen(element, 'name.png')` on the element that shows its result (the event summary,
  a row, a card, the dialog with its error message), never the whole page: the rest of the
  page shows other data of the instance. A few tests also compare a window on the way.
- **Nothing is masked.** Before the shot, `expectScreen` replaces what changes on every run by
  fixed values: IDs (`#1`), UUIDs, the `{timestamp}` of the test data (`{ts}`), today's date and
  the times of day. A date the test typed itself (`2030-06-15`) is kept. For a dialog only its
  content is compared, with the page behind it hidden.
- **Every test** also keeps a screenshot of its last state in the HTML report
  (`screenshot: 'on'`), and a failed test keeps its video and trace.
- A test stopped by a known bug never reaches its final screenshot: its baseline is created
  the first run after the fix.

When a change *intentionally* alters appearance, the relevant tests fail. Review the diff
(`npm run test:e2e:report`), confirm the new look is correct, then:

```bash
npm run test:e2e:update
git add __screenshots__
```

Baselines are platform-suffixed (`*-linux.png`). They must be regenerated on the same OS
the tests run on.

## Not yet covered (future work)

- **CI workflow.** The tests need a MISP instance with the test accounts; a CI job would
  start misp-docker, create the accounts, then run `npm run test:e2e`.
- **The other test plans** of `../` (event, attribute, tag, …): same pattern, one spec
  folder per Markdown folder.
