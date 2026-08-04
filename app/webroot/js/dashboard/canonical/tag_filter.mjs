// `tag_filter` canonical type (PRD §5.5).
//
// Used by the schema-driven configure form's typed-fields tier. The
// canonical value is a structured object — `{ include: string[],
// exclude: string[], taxonomies?: string[], match_event_tags?: bool,
// match_attribute_tags?: bool }` — so this picker renders two chip-
// input controls (include + exclude) and reads back into the object
// shape. forward-compat fields (taxonomies / match_event_tags /
// match_attribute_tags) are not surfaced in the UI yet — the field-
// builder preserves them on round-trip via the `_passthrough` shadow
// state so a config written by a future canonical-aware widget keeps
// its richer shape through an unrelated configure-form save.
//
// Toolbar integration intentionally deferred to a separate Phase 3
// landing: the existing toolbar (toolbar.module.mjs) compares values
// with `String()` (works for scalar canonical types like time_window;
// degrades to `[object Object]` for object types) and reads bulk-
// save values via `input.value` (no `.value` on a structured picker
// root). Adding tag_filter to CANONICAL_REGISTRY requires extending
// the toolbar to dispatch through this module's `readValue()` and
// to compare via the per-type `displayLabel` (or a dedicated `equal`
// hook) — out of scope for this commit. For now, tag_filter is
// configure-form-only.

import { buildChips, getChipsValue } from '../chips.module.mjs';

export const KEY = 'tag_filter';
export const LABEL = 'Tag filter';

// Stash forward-compat fields on the root element so readValue can
// re-emit them unchanged. Keeps the round-trip property intact even
// when a future canonical-aware widget stores taxonomies / match_*
// fields the picker doesn't surface.
const ATTR_PASSTHROUGH = 'data-misp-tagfilter-passthrough';

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') {
      node.addEventListener(k.slice(2), v);
    } else if (v !== null && v !== undefined && v !== false) {
      node.setAttribute(k, v === true ? '' : String(v));
    }
  }
  for (const c of children) {
    if (c == null) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function toStringArray(v) {
  if (!Array.isArray(v)) return [];
  return v.map((x) => (x == null ? '' : String(x))).filter((s) => s !== '');
}

/**
 * Compact display label for the (future) toolbar chip. The current
 * toolbar doesn't render tag_filter yet, but this is the contract a
 * Phase 3 toolbar extension would consume.
 *
 * Examples:
 *   {}                           → "(unset)"
 *   {include:[], exclude:[]}     → "(none)"
 *   {include:[3 tags]}           → "+3"
 *   {exclude:[2 tags]}           → "−2"
 *   {include:[3], exclude:[2]}   → "+3 −2"
 */
export function displayLabel(value) {
  if (!value || typeof value !== 'object') return '(unset)';
  const inc = Array.isArray(value.include) ? value.include.length : 0;
  const exc = Array.isArray(value.exclude) ? value.exclude.length : 0;
  if (inc === 0 && exc === 0) return '(none)';
  if (exc === 0) return `+${inc}`;
  if (inc === 0) return `−${exc}`;
  return `+${inc} −${exc}`;
}

/**
 * Build the tag_filter picker.
 *
 * @param {object|undefined|null} currentValue - canonical tag_filter
 *        object. Missing / non-object input defaults to empty
 *        {include:[], exclude:[]}.
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 *        compact omits the help text tail; schemaKey overrides the
 *        default `data-schema-key` value for widgets that declare
 *        tag_filter under a non-conventional key.
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const value = (currentValue && typeof currentValue === 'object' && !Array.isArray(currentValue))
    ? currentValue
    : {};
  const include = toStringArray(value.include);
  const exclude = toStringArray(value.exclude);
  // Stash forward-compat fields verbatim — they round-trip through
  // readValue unmodified.
  const passthrough = {};
  for (const k of ['taxonomies', 'match_event_tags', 'match_attribute_tags']) {
    if (k in value) passthrough[k] = value[k];
  }

  const includeChips = buildChips(include, {
    placeholder: 'Add include, press Enter',
    ariaLabel: 'Include tag patterns',
    rootClass: 'misp-tag-filter-include',
  });
  const excludeChips = buildChips(exclude, {
    placeholder: 'Add exclude, press Enter',
    ariaLabel: 'Exclude tag patterns',
    rootClass: 'misp-tag-filter-exclude',
  });

  const formatHelp = 'Substring match against full tag names — "tlp:" matches every TLP tag.';
  const canonicalHelp = 'Canonical type — Phase 3 toolbar will bulk-edit this across every widget that declares it.';

  // Root node carries the schema markers so the configure form's
  // readBack finds it. data-type='tag_filter' triggers the
  // structured-readback branch which dispatches to readValue().
  const root = el('div', {
    class: 'misp-field misp-tag-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    el('div', { class: 'misp-tag-filter-row' },
      el('span', { class: 'misp-tag-filter-rowlabel', text: 'Include' }),
      includeChips,
    ),
    el('div', { class: 'misp-tag-filter-row' },
      el('span', { class: 'misp-tag-filter-rowlabel', text: 'Exclude' }),
      excludeChips,
    ),
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? formatHelp : `${formatHelp} ${canonicalHelp}`,
    }),
  );

  // Attach passthrough as a non-DOM property so readValue can find it.
  // (Using a JSON-stringified data-attr would also work but the JSON
  // round-trip can lose number/bool distinctions; a direct property
  // is simpler and lives only as long as the DOM node.)
  if (Object.keys(passthrough).length > 0) {
    root[ATTR_PASSTHROUGH] = passthrough;
  }

  return root;
}

/**
 * Read the current tag_filter value from a picker root element.
 * Dispatched by configure.module.mjs's readBack via the
 * CANONICAL_BUILDERS registry.
 *
 * Always returns an object — include / exclude default to empty
 * arrays so the canonical adapter sees a stable shape. Forward-
 * compat fields (taxonomies / match_event_tags / match_attribute_tags)
 * round-trip from the stashed passthrough; if absent, they're omitted
 * from the result so the adapter doesn't see spurious keys.
 */
export function readValue(rootEl) {
  if (!rootEl) return { include: [], exclude: [] };
  const inc = rootEl.querySelector('.misp-tag-filter-include');
  const exc = rootEl.querySelector('.misp-tag-filter-exclude');
  const out = {
    include: inc ? getChipsValue(inc).map(String) : [],
    exclude: exc ? getChipsValue(exc).map(String) : [],
  };
  const passthrough = rootEl[ATTR_PASSTHROUGH];
  if (passthrough && typeof passthrough === 'object') {
    for (const [k, v] of Object.entries(passthrough)) {
      out[k] = v;
    }
  }
  return out;
}
