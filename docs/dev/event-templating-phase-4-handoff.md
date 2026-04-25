# Handoff notes — Phase 4 (entry points & polish)

Companion to [`event-templating-prd.md`](event-templating-prd.md) and
[`event-templating-progress.md`](event-templating-progress.md). Drop after
Phase 4 lands.

## Branch state

- Branch `templating`, branched off `develop`, ~75 commits ahead.
- Phases 0–3 complete; Phase 4 not started.
- Working tree clean of feature changes. Untracked / `M` noise unchanged
  from the previous handoff (cakephp submodule `m`, taxonomies / galaxy
  submodules `M`, `RustMISP/`, `INSTALL/`, `Plugin/`, `misp-mcp/`,
  `misp-vagrant/`, etc. — all pre-existing, not touched this session).

## Live test instance

- `http://localhost:5007` → vhost at `/var/www/MISP7/app/webroot`.
- REST auth key: `HOST=localhost:5007 AUTH=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- `tests/keys.py` has a stale key — use the env vars above.
- Sample template id=463 (uuid `9cbfa5f7-41bf-4e40-9f9e-e05f286f0ec9`):
  Ransomware / cryptolocker incident, 26 elements, distribution=1, active.
  Only smoke-testable template on the dev instance — do not wipe.
- DB direct access if you need it: `mysql -h localhost -u misp -pPassword1234 misp`.
- If the instance wedges: `sudo systemctl reload php8.3-fpm` (happened
  twice across sessions; mention it to the user, you don't have sudo).

## Phase 4 scope (from progress tracker)

Eight checkboxes, none started:

1. "Add Event → From Template" primary button on events index (both themes)
2. Template picker renders name, description, last-updated, creator org; searchable
3. Events created from a template record `template_uuid` + `template_version`
   in event metadata (location TBD: tag, event note, or dedicated column —
   decide during implementation)
4. Audit log entry on "event created from template" (PRD §5.3 F3.4)
5. Preview mode wired from builder for both themes
6. Import/export UI flows (download button on view, upload form on index)
7. Empty-state and error-state UX (no templates, no compatible object templates, …)
8. User-facing documentation: creator guide and user quickstart

### Things that are arguably done already — verify before re-doing

- **#1 partial**: Phase 2.4 wired the events-index toolbar button on the
  default theme (`12e4ae647`). The Overmind events index has per-row
  actions but no toolbar button — that half is genuinely missing. There's
  also a Phase-3-time `events/add` callout entry point (commits
  `622b21ff9` … `2011249fb`) that's complementary, not a replacement.
- **#2 done?**: Templatepickermodal already shows name + org + modified
  + description + searchable filter on both themes (Phase 2.4 +
  `4a7861945`). Re-verify against the PRD's exact wording before flipping.
- **#6 partial**: Import is wired on the index header (Overmind & default).
  Export is a per-row action. The "download button on view" is missing
  on both themes. The "upload form on index" already redirects to the
  /import page from the header — depending on intent, this might already
  satisfy "upload form".

### #3 — `template_uuid` / `template_version` decision

The PRD leaves the storage location TBD. Three concrete options:

- **Tag** (`misp-galaxy:template_uuid="<uuid>"` or a custom tag): cheapest;
  uses existing infrastructure; gives free filterability via the tag
  index. Downside: tag pollution, no first-class field.
- **Event note**: clean; keeps the metadata visible in the event view;
  not queryable from the events index without a join. Better for human
  readability than for analytics.
- **New `events.template_uuid` + `events.template_version` columns**:
  cleanest analytically (groupable, indexable). Requires a migration,
  REST contract change, and care around event_reports / sync payloads.

Worth pinging the user before committing — this is the one Phase-4 item
where the choice has lasting REST/sync implications.

## Watch-outs that bit me this session

(In addition to the four from the previous handoff, which all still apply.)

### 1. Alpine 3 CDN build auto-boots synchronously

The CDN build's mutation observer is live the moment its `<script>` tag
executes. Any `x-data="foo"` parsed *afterwards* triggers an immediate
factory lookup — if `Alpine.data('foo', …)` hasn't been called yet, it
errors and partially mounts (x-cloak removed, no bindings). See commit
`9a9685f89` for the full diagnosis; the fix is the load order

```
script src=Sortable.min  ← may come before or after, doesn't matter
script src=builder-overmind  ← must register Alpine.data via alpine:init listener
script src=alpine.min  ← boots, fires alpine:init, registers; observer arms
```

If you add another Alpine component anywhere on Overmind, follow the
same pattern: load your script before alpine.min, register inside an
`alpine:init` listener.

### 2. PHP `display_errors=on` injects HTML into `<script>` tags

Any inline `<script>...<?= json_encode($undefinedVar) ?>...</script>`
that references an unset variable explodes the browser with `Unexpected
token '<' at …` because PHP injects `<br /><b>Notice</b>: Undefined
variable…` straight into the script body. Compute every PHP variable
before the `<script>` block uses it. Diagnosed at `c70d70496`.

### 3. MISP classic theme floats — clear or splice

`div.actions` (side menu) floats left at 170px; `div.form` floats right
at `calc(100% - 216px)`. Anything you render as a *sibling* of the form
in `.ctp` files gets squeezed into the gap and visually overlaps the
form. Two clean fixes:

- `clear: both` on the new element (loses the float column geometry —
  the element spans full width below).
- Splice it INSIDE `div.form` via `ob_start` / `ob_get_clean` /
  `strrpos('</div>')` — see `2011249fb` for the events/add callout. Best
  when you want the new element to share the form's column.

`genericForm` has no footer slot; the splice trick is the lightest-touch
way to add content inside it without touching the shared element.

### 4. Cake theme resolution picks element files theme-first

This includes Flash partials. The Overmind Flash overrides at
`Themed/Overmind/Elements/Flash/{info,success,error,warning}.ctp` emit
BS5 markup (`alert-info alert-dismissible fade show m-3`). On pages NOT
in the layout's `$bootstrap5Pages` whitelist (i.e. served with the BS2
layout under the Overmind theme), BS5 CSS isn't loaded → `.fade show`
matches just BS2's `.fade { opacity: 0 }` → invisible alert that takes
layout space for ~5 s before the auto-dismiss JS removes it. **The user
explicitly chose to ignore this** — they expect the colleague-led
Overmind transition to migrate every view eventually. Leave it.

### 5. Index field elements with hidden required keys

- `Fields/shortUUID.ctp` requires `object_type` on the field config or
  it throws `MethodNotAllowedException("No UUID or object_type provided")`
  mid-render. Set it even if the inner element doesn't read the value.
  See `d8a92a224`.
- `Themed/Overmind/Elements/genericElementsBS5/IndexTable/Fields/uuid.ctp`
  defaults a missing `url` to `[]`, then `str_replace`s `%id%` into
  it → returns an array → `h(array)` trips "Array to string conversion".
  Always pass a `url`. See `12aaff357`.

### 6. Carry-overs from the previous handoff that still apply

- `$components = array('RequestHandler', 'Session')` is mandatory on a
  new controller — without it `_isRest()` short-circuits and REST falls
  through to session-auth.
- Cake reads `TINYINT(1)` as PHP bool. On any `edit()`-style re-save,
  coerce `distribution` / `active` back to `int` before `save()` or
  `inList` rejects them strictly.
- `RestResponse->viewData(..., $raw=true)` skips JSON encoding. Pass
  `false` (default) unless you've pre-encoded.

## Key file locations

### Backend (Phase 1 — generally don't touch unless Phase 4 needs it)

- `app/Model/EventTemplate.php` + `EventTemplateObjectDependency.php`
- `app/Lib/Tools/EventTemplate{Validator,Instantiator,Importer,Exporter,InfoRenderer,Dependencies,MarkdownRenderer}.php`
- `app/Controller/EventTemplatesController.php`
- `app/files/schemas/event-template-v1.schema.json`

### Backend additions during Phase 3

- `app/Controller/GalaxyClustersController.php::search()` — Phase 3.4.3
  added the lean `GET /galaxy_clusters/search?galaxy_type=…&q=…`
  endpoint for the user-form's inline cluster picker.

### Default-theme views (Phase 2)

- `app/View/EventTemplates/{index,view,add,edit,preview,user_form,import}.ctp`
- `app/View/Elements/eventTemplates/{builder,userForm,templatePickerModal}/`
- `app/webroot/js/event-templates/{builder,user_form}.js`

### Overmind-theme views (Phase 3)

- `app/View/Themed/Overmind/EventTemplates/*.ctp` — same 7 files
- `app/View/Themed/Overmind/Elements/eventTemplates/{builder,userForm,templatePickerModal}/`
- `app/webroot/js/event-templates/{builder-overmind,user_form_overmind}.js`
- `app/webroot/js/vendor/{sortablejs,alpinejs}/` — vendored deps + LICENSE

### Layout / nav

- `app/View/Themed/Overmind/Layouts/default.ctp` — `$bootstrap5Pages`
  whitelist, currently includes `index, view, add, edit, preview,
  instantiate, import` for `event_templates`.
- `app/View/Helper/NavbarHelper.php` — Overmind navbar; Data ▸ Templates
  group has Event Templates + Add Event Template entries.
- `app/View/Elements/genericElements/SideMenu/side_menu.ctp` — default-
  theme side menu; the `case 'eventTemplates':` block is at line ~1390.

### Entry points

- `app/View/Events/index.ctp` — default-theme toolbar button
  (Phase 2.4); Overmind events index needs the equivalent (Phase 4 #1).
- `app/View/Events/add.ctp` — callout below the form on both themes
  (Phase-3-time, commits `622b21ff9` → `6dd0f14a2` → `2011249fb`).

## Commit protocol reminder

The progress tracker is your spec. One checkbox = one commit by default,
adjacent tightly-coupled checkboxes may merge. Commit message format
prefixed with `[event-template(<sub>)]`, includes PRD + tracker
references in the body, `Co-Authored-By` trailer mandatory. Lint with
`./app/Vendor/bin/parallel-lint --exclude app/Lib/cakephp/ --exclude
app/Vendor/ -e php,ctp app/` before every commit. Stage explicitly with
`git add <paths>`, never `-A` or `.`.

Don't touch existing MISP code outside the new feature's surface unless
the user explicitly signs off — see
`feedback_additive_only_posture.md`. Acceptable touches established
this session: ACL list entries, BS5 layout whitelist, NavbarHelper menu
arrays, `/events/add` view (user-requested entry point).

Good luck. Have fun with #3 — it's the most interesting decision.
