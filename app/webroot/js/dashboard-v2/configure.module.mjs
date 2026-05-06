// dashboard-v2 — Configure side panel (DD-06 two-tier form).
//
// Phase 0.3 prototype: only the `time_window` canonical type is
// implemented in the typed-fields tier; everything else falls into
// the dot-notation key-value tier (DD-06's "Advanced" section). The
// remaining canonical types (tag_filter, org_filter, …) land in
// Phase 3 alongside the toolbar.
//
// Wire value for time_window stays in the legacy `<N>d` form so the
// unmodified widgets still parse it correctly. Phase 2 swaps the
// wire value to ISO 8601 once the canonical→legacy adapter lands —
// see "Discovered work" in dashboard-progress.md.

const ATTR_PANEL          = 'data-misp-configure-root';
const ATTR_BACKDROP       = 'data-misp-configure-backdrop';
const ATTR_BODY           = 'data-misp-configure-body';
const ATTR_TITLE          = 'data-misp-configure-title';
const ATTR_ACTION         = 'data-misp-configure-action';
const ATTR_KV_ACTION      = 'data-misp-kv-action';
const ATTR_WIDGET_CONFIG  = 'data-widget-config';
const ATTR_WIDGET_NAME    = 'data-widget-name';

// Canonical-type catalogue (PRD §5.5 — currently only one entry,
// expanded in Phase 3). The form renders a typed picker for any
// config key in this set; everything else flows into the kv tier.
const CANONICAL_TYPES = new Set(['time_window']);

const TIME_WINDOW_PRESETS = [
  { value: '1d',  label: 'Last 24 hours' },
  { value: '7d',  label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '-1',  label: 'All time' },
];

// Pending state for the currently-open panel.
let openTarget = null;     // the widget element being configured
let onSaveCallback = null; // invoked after a successful save

// ---- shape helpers ----

/** Flatten a nested object/array into dot-notation keys → JSON-encoded
 * scalar values. Arrays are kept as JSON strings so the user can edit
 * them in a single text field; the inverse (`reNest`) parses them back.
 * Round-trip lossless for nested objects, arrays, scalars, booleans. */
function flatten(obj, prefix = '', out = {}) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    out[prefix] = JSON.stringify(obj);
    return out;
  }
  const keys = Object.keys(obj);
  if (keys.length === 0 && prefix) {
    out[prefix] = '{}';
    return out;
  }
  for (const k of keys) {
    const path = prefix ? `${prefix}.${k}` : k;
    flatten(obj[k], path, out);
  }
  return out;
}

/** Re-nest a {dot.path: stringValue} dictionary into a real config
 * object. Each value is JSON-parsed first, falling back to the raw
 * string if it doesn't look like JSON. */
function reNest(flat) {
  const out = {};
  for (const [path, raw] of Object.entries(flat)) {
    const parts = path.split('.');
    let parsed;
    try { parsed = JSON.parse(raw); } catch (_) { parsed = raw; }
    let cur = out;
    for (let i = 0; i < parts.length - 1; i++) {
      if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null
          || Array.isArray(cur[parts[i]])) {
        cur[parts[i]] = {};
      }
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = parsed;
  }
  return out;
}

// ---- DOM construction ----

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

function buildTimeWindowField(currentValue) {
  // Match the closest preset; if the saved value isn't a preset
  // string, append a (stale) "Custom" option so we don't lose it.
  const valueStr = String(currentValue);
  const known = TIME_WINDOW_PRESETS.some((p) => p.value === valueStr);
  const select = el('select', {
    class: 'misp-field-select',
    'data-canonical': 'time_window',
  });
  for (const p of TIME_WINDOW_PRESETS) {
    const opt = el('option', { value: p.value, text: p.label });
    if (p.value === valueStr) opt.selected = true;
    select.appendChild(opt);
  }
  if (!known && currentValue !== undefined) {
    const opt = el('option', {
      value: valueStr,
      text: `${valueStr} (custom)`,
    });
    opt.selected = true;
    select.appendChild(opt);
  }
  return el('label', { class: 'misp-field' },
    el('span', { class: 'misp-field-label', text: 'Time window' }),
    select,
    el('span', {
      class: 'misp-field-help',
      text: 'How far back to look. Canonical type — Phase 3 toolbar will edit this across every widget that declares it.',
    }),
  );
}

function buildKVRow(key, value) {
  return el('li', { class: 'misp-kv-row' },
    el('input', {
      class: 'misp-kv-key',
      type: 'text',
      value: key,
      placeholder: 'key.path',
      'aria-label': 'Config key',
    }),
    el('input', {
      class: 'misp-kv-value',
      type: 'text',
      value,
      placeholder: 'value',
      'aria-label': 'Config value',
    }),
    el('button', {
      type: 'button',
      class: 'misp-widget-iconbtn',
      [ATTR_KV_ACTION]: 'remove',
      title: 'Remove',
      'aria-label': 'Remove',
      text: '✕',
    }),
  );
}

function buildForm(widgetConfig) {
  // Split the config into canonical-typed top-tier and "everything
  // else" bottom-tier. The canonical extraction is a flat lookup —
  // it doesn't recurse into nested keys.
  const canonical = {};
  const rest = {};
  for (const [k, v] of Object.entries(widgetConfig)) {
    if (CANONICAL_TYPES.has(k)) canonical[k] = v;
    else rest[k] = v;
  }
  const flatRest = flatten(rest);

  const typedTier = el('section', { class: 'misp-configure-tier' },
    el('h3', { class: 'misp-configure-tier-title', text: 'Filters' }),
    buildTimeWindowField(canonical.time_window),
  );

  const kvList = el('ul', { class: 'misp-kv-list', 'data-misp-kv-list': '' });
  // If the widget had no non-canonical config yet, seed an empty row
  // so the user has somewhere to start typing — DD-06's "single
  // example key" requirement.
  if (Object.keys(flatRest).length === 0) {
    kvList.appendChild(buildKVRow('', ''));
  } else {
    for (const [k, v] of Object.entries(flatRest)) {
      kvList.appendChild(buildKVRow(k, v));
    }
  }
  const addBtn = el('button', {
    type: 'button',
    class: 'misp-dashboard-btn',
    [ATTR_KV_ACTION]: 'add',
    text: '+ Add row',
  });
  const kvTier = el('section', { class: 'misp-configure-tier' },
    el('h3', { class: 'misp-configure-tier-title', text: 'Advanced' }),
    el('p', {
      class: 'misp-field-help',
      text: 'Other parameters as dot-notation keys. JSON values (arrays, objects, numbers, booleans) are parsed on save.',
    }),
    kvList,
    addBtn,
  );

  return el('div', {}, typedTier, kvTier);
}

// ---- panel control ----

function readBack(panel) {
  const out = {};
  // Top tier: any element with [data-canonical] writes into the root
  // config under its declared canonical key.
  for (const sel of panel.querySelectorAll('[data-canonical]')) {
    const k = sel.getAttribute('data-canonical');
    out[k] = sel.value;
  }
  // Bottom tier: dot-notation rows. Empty keys are skipped (lets the
  // user blank a row to delete it).
  const flat = {};
  for (const row of panel.querySelectorAll('.misp-kv-row')) {
    const k = row.querySelector('.misp-kv-key').value.trim();
    const v = row.querySelector('.misp-kv-value').value;
    if (!k) continue;
    flat[k] = v;
  }
  Object.assign(out, reNest(flat));
  return out;
}

function setHidden(elem, hidden) {
  if (hidden) {
    elem.classList.remove('is-open');
    elem.hidden = true;
  } else {
    elem.hidden = false;
    // Force a reflow so the transition animates from the off-screen
    // start position rather than snapping.
    void elem.offsetWidth;
    elem.classList.add('is-open');
  }
}

export function openConfigure(widgetEl, onSave) {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  if (!panel || !backdrop) {
    console.warn('[misp-dashboard] configure panel markup not found');
    return;
  }
  openTarget = widgetEl;
  onSaveCallback = onSave || null;

  const widgetName = widgetEl.getAttribute(ATTR_WIDGET_NAME) || '';
  const config = JSON.parse(widgetEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}');

  const titleEl = panel.querySelector(`[${ATTR_TITLE}]`);
  if (titleEl) titleEl.textContent = `Configure ${widgetName}`;
  const body = panel.querySelector(`[${ATTR_BODY}]`);
  body.replaceChildren(buildForm(config));

  setHidden(backdrop, false);
  setHidden(panel, false);
  // Focus the first focusable element so keyboard users can act
  // immediately. ESC handler attached at module init.
  const first = panel.querySelector('select, input, button');
  if (first) first.focus();
}

export function closeConfigure() {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  if (!panel || !backdrop) return;
  setHidden(backdrop, true);
  setHidden(panel, true);
  openTarget = null;
  onSaveCallback = null;
}

function commit() {
  if (!openTarget) return;
  const panel = document.querySelector(`[${ATTR_PANEL}]`);
  const newConfig = readBack(panel);
  // Persist back into the widget element so future renders use it.
  // A real save (Phase 1 task: per-widget POST to /updateSettings)
  // hits the same DOM update plus a network round-trip.
  openTarget.setAttribute(ATTR_WIDGET_CONFIG, JSON.stringify(newConfig));
  const target = openTarget;
  const cb = onSaveCallback;
  closeConfigure();
  if (cb) cb(target);
}

// ---- event delegation ----

function init() {
  const root = document.querySelector(`[${ATTR_PANEL}]`);
  if (!root) return;

  // Footer / header buttons (Save, Cancel, ✕).
  root.addEventListener('click', (e) => {
    const trigger = e.target.closest(`[${ATTR_ACTION}]`);
    if (!trigger) return;
    const action = trigger.getAttribute(ATTR_ACTION);
    e.preventDefault();
    if (action === 'cancel') closeConfigure();
    else if (action === 'save') commit();
  });

  // KV-list add/remove buttons.
  root.addEventListener('click', (e) => {
    const trigger = e.target.closest(`[${ATTR_KV_ACTION}]`);
    if (!trigger) return;
    const action = trigger.getAttribute(ATTR_KV_ACTION);
    if (action === 'add') {
      e.preventDefault();
      const list = root.querySelector('.misp-kv-list');
      list.appendChild(buildKVRow('', ''));
      list.lastElementChild.querySelector('.misp-kv-key').focus();
    } else if (action === 'remove') {
      e.preventDefault();
      trigger.closest('.misp-kv-row')?.remove();
    }
  });

  // Backdrop click and ESC key both close the panel.
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  if (backdrop) backdrop.addEventListener('click', closeConfigure);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && openTarget) closeConfigure();
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
