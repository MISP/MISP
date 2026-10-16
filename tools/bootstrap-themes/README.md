# Bootstrap themes

The Bootstrap 5 stylesheets the Overmind UI can load, each built from SCSS
with MISP's own colours (event, object, attribute, ...) merged in.

The compiled output is committed, so a MISP install never needs Node:

- `app/webroot/css/themes/<name>.min.css`: the stylesheet
- `app/webroot/css/themes/<name>.json`: its label, description and mode
- `app/webroot/fonts/themes/*.woff2`: the fonts the stylesheets reference

Only run the build when changing a theme:

```bash
cd tools/bootstrap-themes
npm ci
npm run build
```

Commit the source and the output together. CI rebuilds and fails if the
committed output differs.

## Adding a theme

Create `themes/<name>/` with two files.

`theme.scss` imports, in this order:

```scss
@import "../../scss/misp-functions";
@import "bootswatch/dist/flatly/variables";   // the theme's variables
@import "../../scss/misp-bootstrap";
@import "../../scss/fonts/lato";               // any bundled fonts
@import "bootswatch/dist/flatly/bootswatch";  // the theme's overrides
```

`theme.json`:

```json
{
    "label": "Flatly",
    "description": "Flat and light.",
    "mode": "light",
    "fonts": ["Lato"],
    "hide_from_users": false
}
```

- `mode` is `light`, `dark` or `both`. Only `both` themes get the dark-mode
  toggle; they define their dark palette through Bootstrap's `$*-dark`
  variables.
- To tune a MISP colour for a theme, set it before `misp-bootstrap`, e.g.
  `$misp-object: #8a7f7e;`. The full list is in `scss/_misp-colors.scss`.
- A dark theme can instead set `$misp-lift-colors: true;`, which lightens
  every MISP colour that would fall below 3:1 on its background.
- The top navbar takes the theme's primary as its bar, darkened until white
  text reads on it, and the theme's dropdown colours for its menus. Set
  `$misp-navbar-bg` or `$misp-navbar-accent` before `misp-bootstrap` to
  change the bar; `scss/_misp-navbar.scss` has the full set. The MISP mark
  is drawn white on the bar; `$misp-navbar-brand-filter: none;` keeps its
  colours.
  `"navbar": "builtin"` in `theme.json` keeps the navbar's own palette
  instead: a white bar in light mode, an ink one in dark mode.
- `"navbar": "rail"` replaces that navbar with the rail: a slim bar whose
  groups open as mega-panels (`Elements/navbar_rail.ctp`,
  `js/overmind-rail.js`). The theme imports `../../scss/misp-rail` after
  `misp-bootstrap`. Its defaults are the Hex look; every colour, shape,
  texture and font is a `--misp-rail-*` custom property, listed at the top of
  `scss/_misp-rail.scss`, so a theme re-skins it by setting them on
  `.rail-nav` (and on `[data-bs-theme="dark"] .rail-nav`).
- The build warns when a MISP colour is below 3:1 against the theme's
  background. Either tune it, or accept it in `theme.json`:
  `"contrast_accepted": {"light": ["type"], "dark": ["object"]}`.

## Surfaces in MISP's templates

Some MISP templates colour things inline: distribution badges, file-type
tiles, tag and galaxy chips, the index checkboxes, the sign-in page. They read
`var(--misp-<name>, <Overmind's colour>)`, and `scss/_misp-surfaces.scss`
emits each `--misp-<name>` from the theme's Bootstrap palette, light and dark.

| Token | Overmind (the template's fallback) | Derived for other themes |
|---|---|---|
| `tone-<hue>-bg` / `-fg` / `-border` | the tile's own pastel, e.g. `#fff3cd` / `#856404` | red, yellow, green, cyan, gray: the danger, warning, success, info, secondary subtle trio; blue, indigo, purple, pink, orange, teal: Bootstrap's subtle formula on that colour |
| `tone-<hue>-solid` | the hue itself, e.g. `#198754` for "Completed", `#4cd964` for a switch's on track | the theme colour (red, yellow, green, cyan, gray) or Bootstrap's hue, lifted to 3:1 on the page, its wells and panels, and the theme's modal |
| `surface`, `surface-sunken`, `surface-hover` | `#fff`, `#f8fafc` / `#f8f9fa`, `#f8fafc` | body bg, tertiary bg, secondary bg |
| `line`, `line-strong` | `#ddd`, `#e6ecf2`, `#d8dde3` ...; `#c7d0d9` | text mixed into body bg at 16%, 30% |
| `field-line` | `#d8dde3` | the theme's `$input-border-color`, so inline field edges match `.form-control` |
| `check-off-line`, `check-off-icon` | `#dee2e6`, `#adb5bd` | text mixed into body bg at 30%; at 55%, lifted to 3:1 |
| `ink`, `ink-muted` | `#334`; `#667`, `#888`, `#6c757d` ... | emphasis text; secondary text, lifted to 4.5:1 on those same surfaces where it falls short |
| `dist-0-*` (organisation only) | `#f8d7da` / `#842029` | danger subtle trio |
| `dist-1-*` (this community) | `#ffe5b4` / `#b45309` | subtle formula on `$orange` |
| `dist-2-*` (connected) | `#e7d3c3` / `#5a3e2b` | subtle formula on `$misp-dist-connected` (`#8b5e3c`) |
| `dist-3-*` (all communities) | `#d1f7e0` / `#0f5132` | success subtle trio |
| `dist-4-*` (sharing group) | `#dce8ff` / `#0e146d` | subtle formula on `$blue` |
| `dist-5-*` (inherited) | `#e6b7df` / `#380f33` | subtle formula on `$purple` |
| `dist-unknown-*` | `#f1f1f1` / `#333` | secondary subtle trio |
| `chip-surface`, `chip-raised` | `#fff`, `#fff`; dark `#1d1d18`, `#2a2a24` | body bg, secondary bg |
| `chip-text`, `chip-muted`, `chip-faint` | `#14140f`, `#6b6b63`, `#9b9b92`; dark `#f0f0ea`, `#a3a39a`, `#75756d` | emphasis, secondary and tertiary text |
| `chip-border`, `chip-border-strong`, `chip-raised-border` | `#dededa`, `#c2c2bc`, `#dededa`; dark `#33332c`, `#4a4a42`, `#46463e` | text mixed into body bg at 16%, 30%, 26% |
| `index-check-bg`, `index-actions-bg` | `#fff` | body bg |
| `index-check-border` | `#666` | secondary text |
| `index-check-all` | `orangered` | `$orange` |
| `login-bg` | teal gradient | primary shaded to 65% (dark: primary mixed into the page) |
| `login-card-bg`, `login-heading` | `#ffffff`, `#28191B` | body bg, emphasis text |
| `login-logo-filter` | `none` | `none`; dark `invert(1) hue-rotate(180deg)` |
| `graph-node-*`, `graph-link-*` (`source`, `attribute`, `target`, `org`) | the correlation graph's green, orange, blue and grey | success, orange, blue; links tinted (dark: mixed into the page) |
| `graph-label*`, `graph-lane*`, `graph-axis`, `graph-grid*`, `graph-leader` | near-black labels, green-grey rules | emphasis text, years at 70%, publishers in secondary text; rules are text at 10-35% |
| `graph-accent`, `graph-accent-ink` | `#428bca`, `#2f6c9e` | primary, lifted to 3:1; shaded (dark: tinted) for text |
| `graph-marker*`, `graph-current*` | `#94a9bd`; `#6fbe80` / `#1d4b29` | text mixed into body bg; success and a readable ink |
| `graph-font`, `graph-font-display` | `sans-serif` | the body font; a theme may set a display face for the years |

The `-fg` of a distribution level is its text and glyph colour; `-border` is
its edge. MISP's own logo has near-black lettering, so on a dark card the
filter flips its lightness and keeps its hues; a theme with other artwork in
mind sets `login-logo-filter` itself.

`modal-header-bg` and `modal-header-line` are read by the accented strip atop
add/edit forms but not emitted, so the strip keeps each form's accent unless a
theme sets them.

To change a token, put it in `$misp-surface-overrides` (or
`$misp-surface-overrides-dark`) before `misp-bootstrap`, e.g.
`$misp-surface-overrides: ("login-card-bg": #fdfbf6);`, or declare the custom
property in the theme's own CSS. Overmind sets `$misp-surface-tokens` to
`()`, so its light pages draw the templates' own values. Its dark palette
emits the derived tokens except `chip-*` and `login-*`, which it lists in
`$misp-surface-skip-dark`: the chips carry their own dark values and the
sign-in card stays light.

## Fonts

Themes never load fonts from a third party. A font is bundled by adding an
`@font-face` partial under `scss/fonts/` whose `url()`s point at
`../../fonts/themes/<file>.woff2`, with the matching `@fontsource` package
pinned in `package.json`. The build copies every referenced file from
`node_modules/@fontsource/*/files/`, with the package's license beside it as
`<package>-LICENSE.txt`.

The partials in `scss/fonts/` carry `@fontsource`'s own `unicode-range`
values, so a browser only downloads the subsets a page actually uses.
