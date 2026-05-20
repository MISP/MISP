// `threat_level_filter` canonical type (PRD §5.5).
//
// Multi-select picker for MISP's four event threat-level values.
// Wire shape: int array, subset of {1..4}. Shared between the
// schema-driven configure form (per-widget edit) and the dashboard
// toolbar (bulk edit, DD-05). `Event::fetchEvent` already accepts
// the int array directly under `threat_level_id` (Event.php:3868) —
// CakePHP's IN coercion translates it to a `WHERE threat_level_id
// IN (...)` SQL clause without a post-filter step in the widget.
//
// Empty array = "no filter applied". The picker preserves the
// empty-array shape (rather than collapsing to null) so the widget
// can distinguish "user cleared the filter" from "user never set
// it" — same convention as distribution_filter.
//
// Structurally identical to distribution_filter.mjs except for the
// level vocabulary; when analysis_filter lands as the third int-
// enum-array picker, that's the right trigger for a shared
// `enum_picker.mjs` factory.

export const KEY = 'threat_level_filter';
export const LABEL = 'Threat level';

// MISP's `threat_level_id` enum. Order mirrors the Events index
// filter dropdown so bulk-edit reads familiar.
export const LEVELS = [
  { value: 1, label: 'High',      hint: 'High — sophisticated APT / 0-day' },
  { value: 2, label: 'Medium',    hint: 'Medium — APT malware' },
  { value: 3, label: 'Low',       hint: 'Low — mass-malware' },
  { value: 4, label: 'Undefined', hint: 'Undefined — no threat level set' },
];

const VALID_VALUES = new Set(LEVELS.map((l) => l.value));

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

function toIntArray(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    const n = Number(value);
    return Number.isFinite(n) ? [n | 0] : [];
  }
  const out = [];
  const seen = new Set();
  for (const v of value) {
    const n = Number(v);
    if (!Number.isFinite(n)) continue;
    const i = n | 0;
    if (seen.has(i)) continue;
    seen.add(i);
    out.push(i);
  }
  return out;
}

/**
 * Order-insensitive equality for toolbar mixed-state detection.
 * [1,2] vs [2,1] read as equal so a user who set the same levels in
 * a different order across two widgets doesn't see a spurious
 * "(mixed)" state on the toolbar chip.
 */
export function equal(a, b) {
  const aa = toIntArray(a);
  const bb = toIntArray(b);
  if (aa.length !== bb.length) return false;
  const sa = [...aa].sort((x, y) => x - y);
  const sb = [...bb].sort((x, y) => x - y);
  for (let i = 0; i < sa.length; i++) {
    if (sa[i] !== sb[i]) return false;
  }
  return true;
}

/**
 * Compact display label for the toolbar chip.
 *   []        → "(all)"   no filter applied
 *   [1..4]    → "(all)"   every level = effectively no filter
 *   [1]       → "High"
 *   [1,2]     → "2 levels"
 */
export function displayLabel(value) {
  const arr = toIntArray(value);
  if (arr.length === 0 || arr.length === LEVELS.length) return '(all)';
  if (arr.length === 1) {
    const level = LEVELS.find((l) => l.value === arr[0]);
    return level ? level.label : `Level ${arr[0]}`;
  }
  return `${arr.length} levels`;
}

/**
 * Build the threat_level_filter picker.
 *
 * @param {number[]|number|undefined|null} currentValue
 *        Canonical int array (or scalar legacy). Coerced via
 *        toIntArray; null / unknown shapes default to empty.
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 *        compact omits the canonical-type help tail for the tight
 *        toolbar popover surface; schemaKey overrides the default
 *        `data-schema-key` for widgets that declare
 *        threat_level_filter under a non-conventional key.
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const selected = new Set(toIntArray(currentValue));

  let root;
  const toggles = LEVELS.map((level) => {
    const pressed = selected.has(level.value);
    const btn = el('button', {
      type: 'button',
      class: 'misp-threat-level-toggle',
      'data-threat-level': String(level.value),
      'aria-pressed': pressed ? 'true' : 'false',
      title: level.hint,
      onclick: (e) => {
        e.preventDefault();
        const isPressed = btn.getAttribute('aria-pressed') === 'true';
        btn.setAttribute('aria-pressed', isPressed ? 'false' : 'true');
        root.dispatchEvent(new Event('change', { bubbles: true }));
      },
    }, level.label);
    return btn;
  });

  const formatHelp = 'Filter events by threat level. Empty selection = no filter (any level matches).';
  const canonicalHelp = 'Canonical type — Phase 3 toolbar bulk-edits this across every widget that declares it.';

  root = el('div', {
    class: 'misp-field misp-threat-level-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    el('div', { class: 'misp-threat-level-toggles' }, ...toggles),
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? formatHelp : `${formatHelp} ${canonicalHelp}`,
    }),
  );
  return root;
}

/**
 * Read the picker's current value as a canonical int array.
 * Dispatched by configure.module.mjs's readBack via the
 * CANONICAL_BUILDERS registry, and by toolbar.module.mjs's
 * commitBulk / computeState via the CANONICAL_REGISTRY entry.
 */
export function readValue(rootEl) {
  if (!rootEl) return [];
  const out = [];
  for (const btn of rootEl.querySelectorAll('[data-threat-level][aria-pressed="true"]')) {
    const n = parseInt(btn.getAttribute('data-threat-level'), 10);
    if (Number.isFinite(n) && VALID_VALUES.has(n)) out.push(n);
  }
  return out;
}
