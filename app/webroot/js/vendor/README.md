# `app/webroot/js/vendor/` — third-party JavaScript

Pinned, vendored copies of third-party JavaScript libraries that are not
loaded globally and are not installed through a package manager at build
time. Each library lives in its own sub-directory alongside its upstream
LICENSE file.

## Why vendored, not CDN'd

MISP runs in air-gapped and offline-capable environments. Vendoring keeps
the UI functional without any outbound fetch at page load and pins the
exact bytes shipped with this release.

## Why not in the global asset bundle

The libraries here are scoped to specific views (currently: the
event-template builder in the Overmind theme). Adding them to the
layout-level asset set (`app/View/Themed/Overmind/Layouts/default.ctp`)
or to the `mispOvermind` bundle would push their cost onto every
Overmind page — including high-traffic pages like the events index —
even though the vast majority of requests never need them.

**Loading rule:** include these files per-view via the `$additionalJs`
array in the specific view that needs them. For example, the builder's
`add.ctp` / `edit.ctp` under `app/View/Themed/Overmind/EventTemplates/`
sets `$this->set('additionalJs', ['vendor/sortablejs/Sortable.min', ...])`
before the content fetch. Do **not** add entries for these libraries to
`default.ctp` or to `mispOvermind.js`.

## Inventory

| Library | Pinned version | Path | License | Size (min) | Upstream |
|---|---|---|---|---|---|
| SortableJS | 1.15.7 | `sortablejs/Sortable.min.js` | MIT | ~44 KB | <https://github.com/SortableJS/Sortable> |
| Alpine.js | 3.15.11 | `alpinejs/alpine.min.js` (CDN / IIFE build) | MIT | ~45 KB | <https://github.com/alpinejs/alpine> |

Each sub-directory contains the upstream `LICENSE` file verbatim. The
copyright notices there are the canonical attribution for the bundled
bytes.

## Bumping a pinned version

1. Update the file(s) in the relevant sub-directory.
2. Refresh the `LICENSE` if upstream changed it.
3. Update the version column in the table above.
4. Check the file still matches the size column (or update it).
5. Note the bump in the release notes — vendored changes don't show up
   in `composer.lock` or a package manifest, so the release notes are
   the user-visible audit trail.
