// `org_meta_filter` canonical type (PRD §5.5).
//
// Filter events / orgs by organisation meta-data — vs. `org_filter`
// which filters by org identity. Six structured slots: sector, type,
// nationality, name, uuid, local. Each is a string array (or a small
// int/bool array for `local`); entries may be `!`-prefix-negated.
//
// Canonical and legacy widget shapes match — translation is pure
// pass-through. The picker is the chip-input pattern from tag_filter
// scaled to six rows. readValue assembles a sparse object — empty
// rows are omitted from the output so widgets see the same shape
// they would if the field were never set.
//
// Per-widget acceptance: each consuming widget has a private
// $validFilterKeys array that filters down to the subset it actually
// reads. Setting a `name` chip in the toolbar's bulk-edit propagates
// to all declarers; widgets that don't have `name` in their
// validFilterKeys (OrganisationMapWidget, OrganisationListWidget)
// silently ignore it. The picker shows all six fields uniformly —
// future improvement: per-widget capability hints could narrow the
// picker to only the fields the widget consumes, but the simple
// uniform UX is acceptable for v1.

import { buildChips, getChipsValue } from '../chips.module.mjs';

export const KEY = 'org_meta_filter';
export const LABEL = 'Org meta filter';

const FIELDS = [
  { key: 'sector',      label: 'Sector',      placeholder: 'e.g. Financial' },
  { key: 'type',        label: 'Type',        placeholder: 'e.g. CSIRT' },
  { key: 'nationality', label: 'Nationality', placeholder: 'e.g. DE' },
  { key: 'name',        label: 'Name',        placeholder: 'Org name' },
  { key: 'uuid',        label: 'UUID',        placeholder: 'Org UUID' },
  { key: 'local',       label: 'Local',       placeholder: '0 = remote, 1 = local' },
];

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

function asArrayOf(value) {
  if (!Array.isArray(value)) return [];
  return value;
}

/**
 * Compact display for the toolbar chip. Lists up to 3 non-empty keys
 * as "key:count" pairs; collapses to "(N keys)" beyond that. Empty /
 * non-object input yields "(none)".
 *
 *   {}                                  → "(none)"
 *   {sector:[Financial]}                → "sector:1"
 *   {sector:[A,B], type:[X]}            → "sector:2, type:1"
 *   {sector,type,nationality,name}      → "4 keys"
 */
export function displayLabel(value) {
  if (!value || typeof value !== 'object') return '(none)';
  const filled = [];
  for (const f of FIELDS) {
    const arr = value[f.key];
    if (Array.isArray(arr) && arr.length > 0) filled.push(`${f.key}:${arr.length}`);
  }
  if (filled.length === 0) return '(none)';
  if (filled.length <= 3) return filled.join(', ');
  return `${filled.length} keys`;
}

/**
 * Build the org_meta_filter picker.
 *
 * @param {object|null|undefined} currentValue - canonical org_meta_filter
 *        record. Non-object input defaults to empty.
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const value = (currentValue && typeof currentValue === 'object' && !Array.isArray(currentValue))
    ? currentValue
    : {};

  const rows = FIELDS.map((f) => {
    const chips = buildChips(asArrayOf(value[f.key]), {
      placeholder: f.placeholder,
      ariaLabel: `${f.label} filter entries`,
      rootClass: `misp-org-meta-${f.key}`,
    });
    return el('div', { class: 'misp-org-meta-row' },
      el('span', { class: 'misp-org-meta-rowlabel', text: f.label },),
      chips,
    );
  });

  const formatHelp = 'Each entry may start with "!" to negate. Empty rows are ignored.';
  const canonicalHelp = 'Canonical type — toolbar bulk-edits this across every widget that declares it.';

  const root = el('div', {
    class: 'misp-field misp-org-meta-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    ...rows,
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? formatHelp : `${formatHelp} ${canonicalHelp}`,
    }),
  );
  return root;
}

/**
 * Read the canonical org_meta_filter value from a rendered picker.
 * Returns a sparse object — only keys with at least one chip are
 * included, matching the "unset = field not present" convention the
 * legacy widget's !empty()-guard expects.
 *
 * For the `local` field, chip values that match the legacy 0/1 wire
 * are coerced to integers; other entries pass through as strings.
 * Chip-input's per-chip type marker preserves the original type for
 * a no-touch round-trip ([0,1] stays [0,1] not ["0","1"]).
 */
export function readValue(rootEl) {
  if (!rootEl) return {};
  const out = {};
  for (const f of FIELDS) {
    const chipRoot = rootEl.querySelector(`.misp-org-meta-${f.key}`);
    if (!chipRoot) continue;
    const arr = getChipsValue(chipRoot);
    if (arr.length === 0) continue;
    out[f.key] = arr;
  }
  return out;
}

/**
 * Deep-equality for org_meta_filter values, used by the toolbar's
 * mixed-state detection. Compares as sparse JSON — keys with empty
 * arrays read equal to missing keys (both are "no filter on this
 * field"). The default JSON.stringify compare would call those
 * unequal because key order/presence differs.
 */
export function equal(a, b) {
  return canonicalise(a) === canonicalise(b);
}

function canonicalise(v) {
  if (!v || typeof v !== 'object') return '';
  const parts = [];
  for (const f of FIELDS) {
    const arr = Array.isArray(v[f.key]) ? v[f.key] : [];
    if (arr.length === 0) continue;
    parts.push(f.key + ':' + JSON.stringify(arr));
  }
  return parts.join('|');
}
