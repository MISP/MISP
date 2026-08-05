// `attribute_type_filter` canonical type (PRD §5.5).
//
// Widget-only canonical — not toolbar-eligible per PRD §5.5
// ("doesn't make sense at board level"). The picker is the
// configure form's typed-fields tier; no toolbar chip ships.
//
// Wire shape: { types: string[], categories?: string[] }
//
// Consumer widgets (TrendingAttributesWidget today) historically
// store these as separate top-level keys `type` and `category`;
// the CanonicalTypeAdapter's 1-to-N expansion writes both legacy
// keys at translate time so existing handler logic is untouched.
//
// Picker shape mirrors tag_filter (two chip-input rows). MISP's
// attribute types + categories are static enums (~100 + ~30
// respectively) — a typeahead with a server endpoint would be
// nicer UX, but the chip-input matches the existing user model
// (free-text type names typed by hand, same as $params['type']
// today) and avoids adding a new endpoint for a widget-only
// canonical. Future refinement: pull the type/category catalogue
// from the existing Attribute model and surface as a typeahead.

import { buildChips, getChipsValue } from '../chips.module.mjs';

export const KEY = 'attribute_type_filter';
export const LABEL = 'Attribute type';

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
 * Compact display label (used by the toolbar contract for consistency,
 * even though attribute_type_filter is not toolbar-eligible per PRD).
 */
export function displayLabel(value) {
  if (!value || typeof value !== 'object') return '(unset)';
  const t = Array.isArray(value.types) ? value.types.length : 0;
  const c = Array.isArray(value.categories) ? value.categories.length : 0;
  if (t === 0 && c === 0) return '(none)';
  if (c === 0) return `${t} type${t === 1 ? '' : 's'}`;
  if (t === 0) return `${c} categor${c === 1 ? 'y' : 'ies'}`;
  return `${t}+${c}`;
}

/**
 * Build the attribute_type_filter picker.
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const value = (currentValue && typeof currentValue === 'object' && !Array.isArray(currentValue))
    ? currentValue
    : {};
  const types = toStringArray(value.types);
  const categories = toStringArray(value.categories);

  const typeChips = buildChips(types, {
    placeholder: 'Add type, press Enter (e.g. ip-dst)',
    ariaLabel: 'Attribute types',
    rootClass: 'misp-attribute-filter-types',
  });
  const categoryChips = buildChips(categories, {
    placeholder: 'Add category, press Enter (e.g. Network activity)',
    ariaLabel: 'Attribute categories',
    rootClass: 'misp-attribute-filter-categories',
  });

  const formatHelp = 'Substring-free exact match against Attribute.type / Attribute.category names. Leave both empty for no filter.';
  const canonicalHelp = 'Canonical type — widget-only (PRD §5.5).';

  const root = el('div', {
    class: 'misp-field misp-attribute-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    el('div', { class: 'misp-attribute-filter-row' },
      el('span', { class: 'misp-attribute-filter-rowlabel', text: 'Types' }),
      typeChips,
    ),
    el('div', { class: 'misp-attribute-filter-row' },
      el('span', { class: 'misp-attribute-filter-rowlabel', text: 'Categories' }),
      categoryChips,
    ),
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? formatHelp : `${formatHelp} ${canonicalHelp}`,
    }),
  );

  return root;
}

export function readValue(rootEl) {
  if (!rootEl) return { types: [], categories: [] };
  const t = rootEl.querySelector('.misp-attribute-filter-types');
  const c = rootEl.querySelector('.misp-attribute-filter-categories');
  return {
    types:      t ? getChipsValue(t).map(String) : [],
    categories: c ? getChipsValue(c).map(String) : [],
  };
}
