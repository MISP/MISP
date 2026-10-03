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
- The build warns when a MISP colour is below 3:1 against the theme's
  background. Either tune it, or accept it in `theme.json`:
  `"contrast_accepted": {"light": ["type"], "dark": ["object"]}`.

## Fonts

Themes never load fonts from a third party. A font is bundled by adding an
`@font-face` partial under `scss/fonts/` whose `url()`s point at
`../../fonts/themes/<file>.woff2`, with the matching `@fontsource` package
pinned in `package.json`. The build copies every referenced file from
`node_modules/@fontsource/*/files/`.
