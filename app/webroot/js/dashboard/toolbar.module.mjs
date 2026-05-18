// Dashboard toolbar (DD-05 bulk-edit Model 4).
//
// For every canonical type at least one widget on the dashboard
// declares, render a compact chip in the toolbar slot showing the
// computed display state:
//   - all declarers agree on a value → show that value
//   - declarers disagree → show "(mixed)"
//   - no declarers              → chip is hidden entirely
//
// Clicking a chip opens a popover anchored under it, containing the
// canonical type's shared field builder (same UX as the configure
// form). Pulling a value from the popover walks every widget whose
// current config has that key, writes the new value into each
// widget's data-widget-config, fires the BoardModule's re-render for
// each, and refreshes the chip's computed state.
//
// In Phase 0.3 a "declarer" is detected by the widget's saved config
// having the canonical-type key present. Phase 3 reads `$schema`
// instead — the toolbar API stays the same.

import * as TimeWindow from './canonical/time_window.mjs';

const ATTR_TOOLBAR_SLOT  = 'data-misp-board-toolbar';
const ATTR_WIDGET        = 'data-misp-widget';
const ATTR_WIDGET_CONFIG = 'data-widget-config';
const ATTR_CANONICAL     = 'data-canonical';
const ATTR_CHIP_KEY      = 'data-toolbar-key';

const CANONICAL_REGISTRY = [TimeWindow];

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

/** Collect widgets on the board whose current config has `key`. */
function declarersFor(boardEl, key) {
  const out = [];
  for (const w of boardEl.querySelectorAll(`[${ATTR_WIDGET}]`)) {
    const cfg = readWidgetConfig(w);
    if (Object.prototype.hasOwnProperty.call(cfg, key)) {
      out.push({ el: w, value: cfg[key] });
    }
  }
  return out;
}

/** Compute display state for a canonical type. */
function computeState(boardEl, key) {
  const decls = declarersFor(boardEl, key);
  if (decls.length === 0) return { hidden: true, value: undefined, count: 0 };
  const first = String(decls[0].value);
  const allSame = decls.every((d) => String(d.value) === first);
  return {
    hidden: false,
    value: allSame ? decls[0].value : MIXED,
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

function openPopover(boardEl, canonical, anchorChip) {
  const state = boards.get(boardEl);
  if (!state) return;
  // Toggle: clicking the same chip closes it.
  if (state.openKey === canonical.KEY) {
    closePopover(boardEl);
    return;
  }
  closePopover(boardEl);

  const current = computeState(boardEl, canonical.KEY);
  // For "(mixed)" state, leave the input empty so any committed value
  // overwrites every declarer; the user can also Cancel without harm.
  const seedValue = current.value === MIXED ? '' : current.value;

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

  // Attach to the chip's parent so absolute positioning is relative
  // to it. The chip wrapper's CSS sets position: relative.
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
      const input = popover.querySelector(`[${ATTR_CANONICAL}="${canonical.KEY}"]`);
      const newValue = input ? input.value : '';
      commitBulk(boardEl, canonical.KEY, newValue);
    }
  });

  // Focus the input for keyboard-first users.
  const firstInput = popover.querySelector('input,select,textarea');
  if (firstInput) firstInput.focus();
}

// ---- bulk write ----

function commitBulk(boardEl, key, newValue) {
  const state = boards.get(boardEl);
  if (!state) return;
  const decls = declarersFor(boardEl, key);
  for (const d of decls) {
    const cfg = readWidgetConfig(d.el);
    cfg[key] = newValue;
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
  // Document-level click closes any open popover when the user clicks
  // outside the toolbar slot. Bound once per init.
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
 * Recompute every chip from the current widget configs. Called on
 * boot, after configure-form saves, and after any other write that
 * may have changed declarer state.
 */
export function refresh(boardEl) {
  const state = boards.get(boardEl);
  if (!state) return;
  // Preserve the open-popover key across refreshes so a chip refresh
  // mid-edit doesn't rip the popover out from under the user.
  const wasOpen = state.openKey;
  state.slot.replaceChildren();
  let anyVisible = false;

  for (const canonical of CANONICAL_REGISTRY) {
    const computed = computeState(boardEl, canonical.KEY);
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

    // Re-open the popover if the user was already mid-edit on this
    // chip; uses the new chip element as anchor.
    if (wasOpen === canonical.KEY) openPopover(boardEl, canonical, chip);
  }

  if (!anyVisible) {
    state.slot.appendChild(el('span', {
      class: 'misp-dashboard-toolbar-empty',
      text: 'Toolbar slots will appear here once a widget on this dashboard declares a canonical type.',
    }));
  }
}
