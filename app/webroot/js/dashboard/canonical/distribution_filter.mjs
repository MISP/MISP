// `distribution_filter` canonical type (PRD §5.5).
//
// Multi-select picker for MISP's six event-distribution levels.
// Shared between the schema-driven configure form (per-widget edit)
// and the dashboard toolbar (bulk edit, DD-05). The canonical wire
// shape is an int array — subset of {0..5} — matching the legacy
// `Event::fetchEvent` `distribution` option which CakePHP's IN
// coercion translates directly to a SQL `WHERE distribution IN
// (...)` clause.
//
// Empty array = "no filter applied" (fetchEvent's truthiness guard
// skips the WHERE clause). The picker preserves the empty-array
// shape rather than collapsing to null so the widget can
// distinguish "user cleared the filter" from "user never set it"
// — useful for diagnostics.
//
// The picker renders as a row of toggle buttons (one per level)
// rather than a chip input or a multi-select dropdown because:
//   1. The level count is small + fixed (6 values).
//   2. The set is closed — users never enter free-form values.
//   3. Toggle buttons read better at a glance than checkboxes
//      and avoid the misclick risk of a dropdown.
//
// Toolbar integration (CANONICAL_REGISTRY) requires the per-type
// `readValue` + `equal` exports below — the toolbar uses them for
// bulk-edit dispatch and mixed-state detection respectively.

export const KEY = 'distribution_filter';
export const LABEL = 'Distribution';

// Canonical MISP distribution semantics. Order mirrors the
// dropdown users see in the event edit form so bulk-edit feels
// familiar.
export const LEVELS = [
  { value: 0, label: 'Org only',    hint: 'Your organisation' },
  { value: 1, label: 'Community',   hint: 'This community only' },
  { value: 2, label: 'Connected',   hint: 'Connected communities' },
  { value: 3, label: 'All',         hint: 'All communities' },
  { value: 4, label: 'Sharing grp', hint: 'Sharing group' },
  { value: 5, label: 'Inherit',     hint: 'Inherit from event' },
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

/**
 * Coerce any reasonable input to a deduplicated int array. Handles
 * scalar legacy values, numeric strings, mixed arrays — same shape
 * surface the server adapter's `translateDistributionFilter` covers.
 */
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
 * The toolbar default equality is `JSON.stringify` which would
 * report `[0, 1]` and `[1, 0]` as different; here we compare the
 * sorted-int representation so any permutation of the same set
 * reads as equal.
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
 *   [0..5]    → "(all)"   every level selected = effectively no filter
 *   [0]       → "Org only"
 *   [0,1,2]   → "3 levels"
 *   unknown   → "?"
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
 * Build the distribution_filter picker.
 *
 * @param {number[]|number|undefined|null} currentValue
 *        Canonical int array (or scalar legacy). Coerced via
 *        toIntArray; null / unknown shapes default to empty.
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 *        compact omits the help text tail for tight surfaces
 *        (toolbar popover); schemaKey overrides the default
 *        `data-schema-key` for widgets that declare
 *        distribution_filter under a non-conventional key.
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const selected = new Set(toIntArray(currentValue));

  let root; // forward declaration so toggle handlers can dispatch on it
  const toggles = LEVELS.map((level) => {
    const pressed = selected.has(level.value);
    const btn = el('button', {
      type: 'button',
      class: 'misp-distribution-toggle',
      'data-distribution-level': String(level.value),
      'aria-pressed': pressed ? 'true' : 'false',
      title: level.hint,
      onclick: (e) => {
        e.preventDefault();
        const isPressed = btn.getAttribute('aria-pressed') === 'true';
        btn.setAttribute('aria-pressed', isPressed ? 'false' : 'true');
        // Surface the toggle as a change event so the configure
        // module's debounced live-preview listener picks it up.
        // Bubble true so the listener on the panel body catches it.
        root.dispatchEvent(new Event('change', { bubbles: true }));
      },
    }, level.label);
    return btn;
  });

  const formatHelp = 'Filter events by distribution level. Empty selection = no filter (any level matches).';
  const canonicalHelp = 'Canonical type — Phase 3 toolbar bulk-edits this across every widget that declares it.';

  // Root carries the schema-readback markers. data-type triggers
  // the structured-readback branch in configure.module's readBack
  // which dispatches to this module's readValue().
  root = el('div', {
    class: 'misp-field misp-distribution-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    el('div', { class: 'misp-distribution-toggles' }, ...toggles),
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
 * readNewValue via the CANONICAL_REGISTRY entry.
 */
export function readValue(rootEl) {
  if (!rootEl) return [];
  const out = [];
  for (const btn of rootEl.querySelectorAll('[data-distribution-level][aria-pressed="true"]')) {
    const n = parseInt(btn.getAttribute('data-distribution-level'), 10);
    if (Number.isFinite(n) && VALID_VALUES.has(n)) out.push(n);
  }
  return out;
}
