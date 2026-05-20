// Dashboard toolbar (DD-05 bulk-edit Model 4).
//
// For every canonical type declared by at least one widget on the
// board (via $schema), render a compact chip showing the consensus
// value across those declarers:
//   - all declarers agree on a value → show that value
//   - declarers disagree            → show "(mixed)"
//   - no declarers                  → chip is hidden entirely
//
// Clicking a chip opens a popover anchored beneath it, containing
// the canonical type's shared field builder (same UX surface as the
// configure form). Pulling a value walks every declarer, writes the
// new value into that declarer's `config[schemaKey]`, fires the
// BoardModule's re-render callback for each, and refreshes the chip.
//
// Declarer detection is schema-driven per PRD §5.5. A "declarer" is
// every (widget, schemaKey) pair where the widget's $schema entry
// for schemaKey has `type === canonical.KEY`. This handles widgets
// that declare a canonical type under a non-conventional schema key
// (e.g. RecentSightingsWidget uses `last` for `time_window`).
//
// Per-canonical dispatch:
//   - canonical.buildField(value, {compact: true}) renders the popover
//     control. The root carries `data-canonical=<KEY>` so commit can
//     find it again.
//   - canonical.readValue(rootEl) reads the current value from the
//     rendered control. Required for structured types (tag_filter
//     etc.) whose value isn't a single .value scalar.
//   - canonical.equal(a, b) determines mixed-state (optional;
//     defaults to JSON.stringify deep-equal for objects + String()
//     compare for scalars).
//   - canonical.displayLabel(value) renders the chip's compact label.

import * as TimeWindow        from './canonical/time_window.mjs';
import * as TagFilter         from './canonical/tag_filter.mjs';
import * as OrgMetaFilter     from './canonical/org_meta_filter.mjs';
import * as DistributionFilter from './canonical/distribution_filter.mjs';
import * as ThreatLevelFilter from './canonical/threat_level_filter.mjs';
import * as AnalysisFilter    from './canonical/analysis_filter.mjs';

const ATTR_TOOLBAR_SLOT  = 'data-misp-board-toolbar';
const ATTR_WIDGET        = 'data-misp-widget';
const ATTR_WIDGET_CONFIG = 'data-widget-config';
const ATTR_WIDGET_SCHEMA = 'data-widget-schema';
const ATTR_CANONICAL     = 'data-canonical';
const ATTR_CHIP_KEY      = 'data-toolbar-key';

const CANONICAL_REGISTRY = [TimeWindow, TagFilter, OrgMetaFilter, DistributionFilter, ThreatLevelFilter, AnalysisFilter];

const MIXED = '__mixed__';

// Per-board state. Toolbar is mounted once per page so a single Map
// keyed by board root is fine, but in practice we only ever see one.
const boards = new WeakMap();   // boardEl → { slot, onWidgetChange, openKey }

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

// ---- declarer scan ----

function readWidgetConfig(widgetEl) {
  try {
    return JSON.parse(widgetEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}');
  } catch (_) {
    return {};
  }
}

function readWidgetSchema(widgetEl) {
  try {
    const s = JSON.parse(widgetEl.getAttribute(ATTR_WIDGET_SCHEMA) || '{}');
    return (s && typeof s === 'object' && !Array.isArray(s)) ? s : {};
  } catch (_) {
    return {};
  }
}

/**
 * Walk the board's widgets and return every (widget, schemaKey, value)
 * tuple whose $schema declares the canonical type. A widget that
 * declares the same canonical type under two schema keys contributes
 * two entries — bulk-edit writes to both naturally.
 */
function declarersFor(boardEl, canonicalKey) {
  const out = [];
  for (const w of boardEl.querySelectorAll(`[${ATTR_WIDGET}]`)) {
    const schema = readWidgetSchema(w);
    const cfg = readWidgetConfig(w);
    for (const [schemaKey, entry] of Object.entries(schema)) {
      if (!entry || typeof entry !== 'object' || entry.type !== canonicalKey) continue;
      out.push({ el: w, schemaKey, value: cfg[schemaKey] });
    }
  }
  return out;
}

/**
 * Default equality for mixed-state detection. Scalars compare via
 * String() (so '7d' === '7d' but also so legacy mixed types '90d'
 * vs canonical 'P90D' read as different — which is intentional;
 * showing them as agreeing would mask the canonical-vs-legacy
 * inconsistency). Objects/arrays compare via JSON.stringify — fine
 * for tag_filter's structured value where the two halves emerge
 * from the same builder so key ordering is stable.
 */
function defaultEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return a == null && b == null;
  if (typeof a === 'object' && typeof b === 'object') {
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return String(a) === String(b);
}

/** Compute display state for a canonical type. */
function computeState(boardEl, canonical) {
  const decls = declarersFor(boardEl, canonical.KEY);
  if (decls.length === 0) return { hidden: true, value: undefined, count: 0 };
  const eq = canonical.equal || defaultEqual;
  const first = decls[0].value;
  const allSame = decls.every((d) => eq(d.value, first));
  return {
    hidden: false,
    value: allSame ? first : MIXED,
    count: decls.length,
  };
}

// ---- chip rendering ----

function chipLabel(canonical, value) {
  if (value === MIXED) return '(mixed)';
  return canonical.displayLabel
    ? canonical.displayLabel(value)
    : String(value ?? '');
}

function buildChip(canonical, state) {
  const chip = el('button', {
    type: 'button',
    class: 'misp-toolbar-chip',
    [ATTR_CHIP_KEY]: canonical.KEY,
    'aria-haspopup': 'dialog',
    'aria-expanded': 'false',
    title: `Bulk edit ${canonical.LABEL.toLowerCase()} across ${state.count} widget${state.count === 1 ? '' : 's'}`,
  },
    el('span', { class: 'misp-toolbar-chip-label', text: `${canonical.LABEL}:` }),
    el('span', { class: 'misp-toolbar-chip-value', text: chipLabel(canonical, state.value) }),
    el('span', { class: 'misp-toolbar-chip-caret', text: '▾' }),
  );
  if (state.value === MIXED) chip.classList.add('is-mixed');
  return chip;
}

// ---- popover ----

function closePopover(boardEl) {
  const state = boards.get(boardEl);
  if (!state) return;
  const existing = state.slot.querySelector('.misp-toolbar-popover');
  if (existing) existing.remove();
  const expanded = state.slot.querySelector('[aria-expanded="true"]');
  if (expanded) expanded.setAttribute('aria-expanded', 'false');
  state.openKey = null;
}

function readNewValue(canonical, popoverEl) {
  // The canonical's buildField marks its rootEl with data-canonical.
  // For structured types (tag_filter) the rootEl is a container <div>;
  // for scalar types (time_window) it's the inner <input>. Both are
  // discoverable by the same selector. readValue dispatch handles
  // the per-type readback shape.
  const fieldRoot = popoverEl.querySelector(`[${ATTR_CANONICAL}="${canonical.KEY}"]`);
  if (!fieldRoot) return undefined;
  if (typeof canonical.readValue === 'function') {
    return canonical.readValue(fieldRoot);
  }
  // Scalar fallback for canonical types that haven't ported to the
  // readValue contract yet — read .value off the field root.
  return fieldRoot.value;
}

function openPopover(boardEl, canonical, anchorChip) {
  const state = boards.get(boardEl);
  if (!state) return;
  if (state.openKey === canonical.KEY) {
    closePopover(boardEl);
    return;
  }
  closePopover(boardEl);

  const current = computeState(boardEl, canonical);
  // For "(mixed)" state, hand the builder an explicit empty value
  // (null for objects, '' for scalars) so the user can choose any new
  // value without inheriting one declarer's bias.
  const seedValue = current.value === MIXED ? null : current.value;

  const popover = el('div', {
    class: 'misp-toolbar-popover',
    role: 'dialog',
    'aria-label': `Bulk edit ${canonical.LABEL}`,
  });
  const fieldHost = el('div', { class: 'misp-toolbar-popover-body' },
    canonical.buildField(seedValue, { compact: true }),
    current.value === MIXED
      ? el('p', {
          class: 'misp-field-help',
          text: `${current.count} widgets have different values. Saving overwrites every one.`,
        })
      : null,
  );
  const cancel = el('button', {
    type: 'button',
    class: 'misp-dashboard-btn',
    'data-popover-action': 'cancel',
    text: 'Cancel',
  });
  const save = el('button', {
    type: 'button',
    class: 'misp-dashboard-btn misp-dashboard-btn-primary',
    'data-popover-action': 'save',
    text: `Apply to ${current.count} widget${current.count === 1 ? '' : 's'}`,
  });
  popover.append(
    fieldHost,
    el('div', { class: 'misp-toolbar-popover-footer' }, cancel, save),
  );

  const wrap = anchorChip.parentElement;
  wrap.appendChild(popover);

  anchorChip.setAttribute('aria-expanded', 'true');
  state.openKey = canonical.KEY;

  popover.addEventListener('click', (e) => {
    const trigger = e.target.closest('[data-popover-action]');
    if (!trigger) return;
    const action = trigger.getAttribute('data-popover-action');
    e.preventDefault();
    if (action === 'cancel') closePopover(boardEl);
    else if (action === 'save') {
      const newValue = readNewValue(canonical, popover);
      commitBulk(boardEl, canonical, newValue);
    }
  });

  const firstInput = popover.querySelector('input,select,textarea');
  if (firstInput) firstInput.focus();
}

// ---- bulk write ----

function commitBulk(boardEl, canonical, newValue) {
  const state = boards.get(boardEl);
  if (!state) return;
  const decls = declarersFor(boardEl, canonical.KEY);
  for (const d of decls) {
    const cfg = readWidgetConfig(d.el);
    cfg[d.schemaKey] = newValue;
    d.el.setAttribute(ATTR_WIDGET_CONFIG, JSON.stringify(cfg));
    if (state.onWidgetChange) state.onWidgetChange(d.el);
  }
  closePopover(boardEl);
  refresh(boardEl);
}

// ---- public API ----

export function initToolbar(boardEl, opts = {}) {
  const slotSelector = `[${ATTR_TOOLBAR_SLOT}]`;
  const slot = document.querySelector(slotSelector);
  if (!slot) return;
  boards.set(boardEl, {
    slot,
    onWidgetChange: opts.onWidgetChange || null,
    openKey: null,
  });
  document.addEventListener('click', (e) => {
    const inSlot = e.target.closest(slotSelector);
    if (!inSlot && boards.get(boardEl)?.openKey) closePopover(boardEl);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && boards.get(boardEl)?.openKey) closePopover(boardEl);
  });
  refresh(boardEl);
}

/**
 * Snapshot of every canonical type's current toolbar state for which
 * the board has at least one declarer AND every declarer agrees on
 * the value (non-mixed). Returns a plain object keyed by canonical
 * KEY → value. Used by the BoardModule's Add Widget placement path
 * to implement PRD F5.6.4 (new tile inherits the toolbar's
 * non-mixed display values), but kept generic so any future
 * "consume the toolbar's current view" caller can use it too.
 *
 * Mixed and absent canonicals are omitted — the caller never has to
 * special-case the MIXED sentinel or distinguish "no declarers" from
 * "all declarers default".
 */
export function currentValues(boardEl) {
  const out = {};
  for (const canonical of CANONICAL_REGISTRY) {
    const state = computeState(boardEl, canonical);
    if (state.hidden) continue;
    if (state.value === MIXED) continue;
    out[canonical.KEY] = state.value;
  }
  return out;
}

/**
 * Recompute every chip from the current widget configs + schemas.
 * Called on boot, after configure-form saves, and after any other
 * write that may have changed declarer state.
 */
export function refresh(boardEl) {
  const state = boards.get(boardEl);
  if (!state) return;
  const wasOpen = state.openKey;
  state.slot.replaceChildren();
  let anyVisible = false;

  for (const canonical of CANONICAL_REGISTRY) {
    const computed = computeState(boardEl, canonical);
    if (computed.hidden) continue;
    anyVisible = true;
    const wrap = el('div', { class: 'misp-toolbar-slot' });
    const chip = buildChip(canonical, computed);
    chip.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openPopover(boardEl, canonical, chip);
    });
    wrap.appendChild(chip);
    state.slot.appendChild(wrap);

    if (wasOpen === canonical.KEY) openPopover(boardEl, canonical, chip);
  }

  if (!anyVisible) {
    state.slot.appendChild(el('span', {
      class: 'misp-dashboard-toolbar-empty',
      text: 'Toolbar slots will appear here once a widget on this dashboard declares a canonical type.',
    }));
  }
}
