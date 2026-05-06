# Pragmatic Drag and Drop — vendoring notes

The dashboard v2 grid module uses Atlassian's
[Pragmatic Drag and Drop](https://atlassian.design/components/pragmatic-drag-and-drop/)
for drag/drop primitives. We vendor a bundled, self-contained ESM
build so the dashboard never depends on a runtime CDN or a permanent
JS build pipeline in MISP. Decision: see
`docs/dev/dashboard-design-decisions.md` DD-01.

## Files in this directory

| File | Origin |
|---|---|
| `pragmatic-drag-and-drop.bundle.mjs` | Built locally with esbuild from the npm package + only the entry points dashboard-v2 uses. ESM, minified, 21.5KB raw / ~6.8KB gzipped. |
| `LICENSE.pragmatic-drag-and-drop.md` | The package's upstream `LICENSE.md` (Apache 2.0, Copyright 2022 Atlassian Pty Ltd), copied verbatim. Required by the licence. |
| `VENDORING.md` | This file. |

## Reproducing the bundle

```bash
mkdir -p /tmp/pdd-bundle && cd /tmp/pdd-bundle
npm init -y > /dev/null
npm install --silent --no-audit --no-fund \
  @atlaskit/pragmatic-drag-and-drop@1.8.1 esbuild@0.24.0

cat > entry.mjs <<'EOF'
export {
  draggable,
  dropTargetForElements,
  monitorForElements,
} from '@atlaskit/pragmatic-drag-and-drop/element/adapter';
export { combine } from '@atlaskit/pragmatic-drag-and-drop/combine';
EOF

./node_modules/.bin/esbuild entry.mjs \
  --bundle --format=esm --target=es2022 --minify \
  --legal-comments=external \
  --outfile=pragmatic-drag-and-drop.bundle.mjs

# Then copy the bundle and the upstream LICENSE.md into this directory:
cp pragmatic-drag-and-drop.bundle.mjs \
   /var/www/MISP7/app/webroot/js/dashboard-v2/grid/vendor/
cp node_modules/@atlaskit/pragmatic-drag-and-drop/LICENSE.md \
   /var/www/MISP7/app/webroot/js/dashboard-v2/grid/vendor/LICENSE.pragmatic-drag-and-drop.md
```

Same package version + same esbuild version + same entry file → byte-identical
bundle output.

## Exported names

The bundle re-exports four names (everything the GridModule consumes):

- `draggable(opts)` — make a DOM element draggable.
- `dropTargetForElements(opts)` — make a DOM element a valid drop target.
- `monitorForElements(opts)` — observe drag activity globally without
  having a specific draggable / drop target.
- `combine(...cleanups)` — chain together cleanup functions returned by
  the above.

All consumed via:

```js
import { draggable, dropTargetForElements, monitorForElements, combine }
  from '/js/dashboard-v2/grid/vendor/pragmatic-drag-and-drop.bundle.mjs';
```

## Adding more entry points later

If GridModule ends up needing other PDD entry points
(e.g. `external/adapter` for file drops, `text-selection/adapter` for
text drag-handles), add them to `entry.mjs` and rebuild. Keep the
`exports` block in this file in sync so a fresh session can see at a
glance what's in the bundle.

## Upgrading PDD

Bump the version pin in the install command, rerun the build, commit.
Test the GridModule against the new bundle before merging — PDD's
public API is stable but minor versions occasionally tighten types
or rename internals.

## Why bundled, not raw

PDD's npm package is published as ESM with internal cross-package
imports (`bind-event-listener`, `raf-schd`, `@babel/runtime`). Loading
it raw in the browser without a bundler means either chasing each
import to a CDN or shipping all those packages individually. Bundling
once at vendoring time gives us one self-contained file that loads via
a single `<script type="module">` and has no runtime CDN dependency.
