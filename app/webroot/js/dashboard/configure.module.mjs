// Configure side panel (DD-06 two-tier form).
//
// The typed-fields tier is **schema-driven** (PRD §5.7): for each
// entry in the widget's $schema, render a type-aware control if a
// builder exists for the entry's type. Entries without a builder
// (Phase 3 canonical types, exotic scalars) fall through to the
// dot-notation key-value tier so their values stay editable.
//
// Per-canonical-type field builders live under `canonical/`; this
// module composes them with the dot-notation kv tier and the panel
// chrome. The toolbar (toolbar.module.mjs) reuses the same field
// builders. Phase 3 brings tag_filter / org_filter / etc. into the
// canonical registry below.

import * as TimeWindow from './canonical/time_window.mjs';
import { buildChips, getChipsValue } from './chips.module.mjs';
import {
  flatten,
  reNest,
  asArray,
  seedFromPlaceholder,
} from './kvshape.module.mjs';

// Builder registry keyed by canonical type name. Each builder
// exports `KEY` (the type), `LABEL`, and `buildField(value, opts)`
// returning a DOM node whose innermost <input>/<select> carries the
// `data-schema-key` attribute set by the configure form (so the
// readback finds it without knowing the builder).
const CANONICAL_BUILDERS = {
  [TimeWindow.KEY]: TimeWindow,
};
const SCALAR_TYPES = new Set(['string', 'int', 'bool', 'enum']);

const ATTR_PANEL              = 'data-misp-configure-root';
const ATTR_BACKDROP           = 'data-misp-configure-backdrop';
const ATTR_BODY               = 'data-misp-configure-body';
const ATTR_TITLE              = 'data-misp-configure-title';
const ATTR_ACTION             = 'data-misp-configure-action';
const ATTR_KV_ACTION          = 'data-misp-kv-action';
const ATTR_WIDGET_CONFIG      = 'data-widget-config';
const ATTR_WIDGET_SCHEMA      = 'data-widget-schema';
const ATTR_WIDGET_PLACEHOLDER = 'data-widget-placeholder';
const ATTR_WIDGET_NAME        = 'data-widget-name';
const ATTR_SCHEMA_KEY         = 'data-schema-key';

// Pending state for the currently-open panel.
let openTarget = null;          // the widget element being configured
let onSaveCallback = null;      // invoked after a successful save
let onPreviewCallback = null;   // invoked on each debounced form-input change
let originalConfigJson = null;  // snapshot of data-widget-config at open
let previewTimer = null;        // debounce handle for live preview
let dirty = false;              // any input/change event seen since open
let savedThisSession = false;   // commit sets true so closeConfigure skips the revert

// Live-preview debounce in ms (DD-06: "debounced 250ms re-render of
// the widget on form-input change").
const PREVIEW_DEBOUNCE_MS = 250;

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

function buildKVRow(key, value) {
  const arr = asArray(value);
  const valueControl = (arr !== null)
    ? buildChips(arr, {
        placeholder: 'Add value, press Enter',
        ariaLabel: 'Config value (array of chips)',
        rootClass: 'misp-kv-chips',
      })
    : el('input', {
        class: 'misp-kv-value',
        type: 'text',
        value,
        placeholder: 'value',
        'aria-label': 'Config value',
      });
  return el('li', { class: 'misp-kv-row' },
    el('input', {
      class: 'misp-kv-key',
      type: 'text',
      value: key,
      placeholder: 'key.path',
      'aria-label': 'Config key',
    }),
    valueControl,
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

/**
 * Build a native form control for a scalar-typed schema entry.
 * Returns a DOM node whose inner input/select carries the
 * data-schema-key attribute the readback uses to map back to the
 * config key.
 */
function buildScalarField(key, entry, currentValue) {
  const help = entry.help || '';
  const label = el('span', { class: 'misp-field-label', text: key });
  let control;
  switch (entry.type) {
    case 'bool': {
      const checked = currentValue === undefined
        ? Boolean(entry.default)
        : Boolean(currentValue);
      control = el('input', {
        type: 'checkbox',
        class: 'misp-field-checkbox',
        [ATTR_SCHEMA_KEY]: key,
        'data-type': 'bool',
        'aria-label': key,
      });
      if (checked) control.setAttribute('checked', '');
      break;
    }
    case 'enum': {
      control = el('select', {
        class: 'misp-field-input',
        [ATTR_SCHEMA_KEY]: key,
        'data-type': 'enum',
        'aria-label': key,
      });
      const opts = Array.isArray(entry.enum) ? entry.enum : [];
      const cur = currentValue !== undefined
        ? String(currentValue)
        : (entry.default !== undefined ? String(entry.default) : '');
      for (const o of opts) {
        const opt = el('option', { value: String(o), text: String(o) });
        if (String(o) === cur) opt.setAttribute('selected', '');
        control.appendChild(opt);
      }
      break;
    }
    case 'int': {
      const v = currentValue !== undefined
        ? currentValue
        : (entry.default !== undefined ? entry.default : '');
      control = el('input', {
        type: 'number',
        step: '1',
        class: 'misp-field-input',
        [ATTR_SCHEMA_KEY]: key,
        'data-type': 'int',
        value: v === '' ? '' : String(v),
        'aria-label': key,
      });
      break;
    }
    case 'string':
    default: {
      const v = currentValue !== undefined
        ? currentValue
        : (entry.default !== undefined ? entry.default : '');
      control = el('input', {
        type: 'text',
        class: 'misp-field-input',
        [ATTR_SCHEMA_KEY]: key,
        'data-type': 'string',
        value: v === '' ? '' : String(v),
        'aria-label': key,
      });
      break;
    }
  }
  const children = [label, control];
  if (help) {
    children.push(el('span', { class: 'misp-field-help', text: help }));
  }
  return el('label', { class: 'misp-field' }, ...children);
}

function buildForm(widgetConfig, widgetSchema, widgetPlaceholder) {
  // Top tier: iterate the widget's $schema entries. For each entry,
  // route by type — canonical types with a registered builder render
  // the type-aware field; scalar types render native controls; entries
  // with no available builder fall through to the bottom tier so the
  // user can still see and edit the saved value.
  //
  // Schema entries are tagged with their schema key via the builder's
  // existing `data-schema-key` (formerly `data-canonical`) attribute,
  // injected by setting `KEY = <schema_key>` on each builder call.
  const handledKeys = new Set();
  const typedFields = [];
  const schemaEntries = (widgetSchema && typeof widgetSchema === 'object')
    ? widgetSchema
    : {};
  for (const [key, entry] of Object.entries(schemaEntries)) {
    if (!entry || typeof entry !== 'object' || !entry.type) continue;
    const type = entry.type;
    if (CANONICAL_BUILDERS[type]) {
      // Canonical: dispatch to the registered builder. The builder
      // returns a node whose <input>/<select> carries data-schema-key.
      typedFields.push(CANONICAL_BUILDERS[type].buildField(
        widgetConfig[key],
        { schemaKey: key }
      ));
      handledKeys.add(key);
    } else if (SCALAR_TYPES.has(type)) {
      typedFields.push(buildScalarField(key, entry, widgetConfig[key]));
      handledKeys.add(key);
    }
    // Unbuilt canonical types (Phase 3) fall through — the schema
    // entry's saved value will surface in the bottom tier below
    // because handledKeys doesn't include it.
  }

  // Bottom tier gets every config key NOT handled by the top tier.
  const rest = {};
  for (const [k, v] of Object.entries(widgetConfig)) {
    if (!handledKeys.has(k)) rest[k] = v;
  }
  const flatRest = flatten(rest);

  const formNodes = [];
  if (typedFields.length > 0) {
    formNodes.push(el('section', { class: 'misp-configure-tier' },
      el('h3', { class: 'misp-configure-tier-title', text: 'Filters' }),
      ...typedFields,
    ));
  }

  const kvList = el('ul', { class: 'misp-kv-list', 'data-misp-kv-list': '' });
  // If the widget had no bottom-tier config yet, seed from the
  // widget's $placeholder JSON (DD-06 "example keys/values from the
  // placeholder"); fall back to a single empty row when the
  // placeholder is absent, malformed, or contains only schema-handled
  // keys after filtering.
  if (Object.keys(flatRest).length === 0) {
    const seedRows = seedFromPlaceholder(widgetPlaceholder, handledKeys);
    if (seedRows.length === 0) {
      kvList.appendChild(buildKVRow('', ''));
    } else {
      for (const [k, v] of seedRows) {
        kvList.appendChild(buildKVRow(k, v));
      }
    }
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
  formNodes.push(el('section', { class: 'misp-configure-tier' },
    el('h3', { class: 'misp-configure-tier-title', text: 'Advanced' }),
    el('p', {
      class: 'misp-field-help',
      text: 'Other parameters as dot-notation keys. JSON values (arrays, objects, numbers, booleans) are parsed on save.',
    }),
    kvList,
    addBtn,
  ));

  return el('div', {}, ...formNodes);
}

// ---- panel control ----

function readBack(panel) {
  const out = {};
  // Top tier: every control tagged with [data-schema-key] writes
  // into the root config under its key. data-type drives coercion
  // (checkboxes → bool, number inputs → int, selects/text → string).
  for (const sel of panel.querySelectorAll(`[${ATTR_SCHEMA_KEY}]`)) {
    const k = sel.getAttribute(ATTR_SCHEMA_KEY);
    const t = sel.getAttribute('data-type');
    let v;
    if (sel.type === 'checkbox') {
      v = sel.checked;
    } else if (t === 'int') {
      // Empty string stays empty so the widget's empty-fallback can
      // engage; otherwise coerce to number (NaN is treated as empty).
      if (sel.value === '') {
        v = '';
      } else {
        const n = Number(sel.value);
        v = Number.isFinite(n) ? Math.trunc(n) : sel.value;
      }
    } else {
      v = sel.value;
    }
    out[k] = v;
  }
  // Bottom tier: dot-notation rows. Empty keys are skipped (lets the
  // user blank a row to delete it). For rows whose value column is a
  // chip-input (array-typed value), read the chip array and JSON-
  // stringify back into the flat shape reNest expects.
  const flat = {};
  for (const row of panel.querySelectorAll('.misp-kv-row')) {
    const k = row.querySelector('.misp-kv-key').value.trim();
    if (!k) continue;
    const chipRoot = row.querySelector('.misp-kv-chips');
    let v;
    if (chipRoot) {
      v = JSON.stringify(getChipsValue(chipRoot));
    } else {
      v = row.querySelector('.misp-kv-value').value;
    }
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

/**
 * Open the configure side panel for the given widget element.
 *
 * @param {HTMLElement} widgetEl - the widget being configured.
 * @param {{onSave?: function, onPreview?: function}|function} [opts]
 *        - onSave(widgetEl)   - invoked after a successful Save.
 *        - onPreview(widgetEl) - invoked after each debounced
 *          form-input change AND after a Cancel (with the original
 *          config restored), so the caller can re-render the widget.
 *        For backwards compatibility, a bare function is treated as
 *        onSave with no onPreview.
 */
export function openConfigure(widgetEl, opts) {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  if (!panel || !backdrop) {
    console.warn('[misp-dashboard] configure panel markup not found');
    return;
  }
  if (typeof opts === 'function') {
    opts = { onSave: opts };
  }
  opts = opts || {};
  openTarget = widgetEl;
  onSaveCallback = opts.onSave || null;
  onPreviewCallback = opts.onPreview || null;
  originalConfigJson = widgetEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}';
  dirty = false;
  savedThisSession = false;
  if (previewTimer) {
    clearTimeout(previewTimer);
    previewTimer = null;
  }

  const widgetName = widgetEl.getAttribute(ATTR_WIDGET_NAME) || '';
  const config = JSON.parse(widgetEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}');
  let schema = {};
  try {
    schema = JSON.parse(widgetEl.getAttribute(ATTR_WIDGET_SCHEMA) || '{}');
    if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
      schema = {};
    }
  } catch (_) {
    schema = {};
  }
  // Raw placeholder string — seedFromPlaceholder() owns the parse +
  // fallback path so it can tolerate legacy malformed JSON.
  const placeholder = widgetEl.getAttribute(ATTR_WIDGET_PLACEHOLDER) || '';

  const titleEl = panel.querySelector(`[${ATTR_TITLE}]`);
  if (titleEl) titleEl.textContent = `Configure ${widgetName}`;
  const body = panel.querySelector(`[${ATTR_BODY}]`);
  body.replaceChildren(buildForm(config, schema, placeholder));

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
  if (previewTimer) {
    clearTimeout(previewTimer);
    previewTimer = null;
  }
  // Cancel path: if the user made staged edits via live preview but
  // didn't save (cancel button, ✕, Escape, backdrop click), restore
  // the original config to data-widget-config and re-render the
  // widget so the visible state reverts to pre-open. commit() sets
  // savedThisSession=true so this branch is skipped on Save.
  if (dirty && !savedThisSession && openTarget) {
    openTarget.setAttribute(ATTR_WIDGET_CONFIG, originalConfigJson);
    if (onPreviewCallback) onPreviewCallback(openTarget);
  }
  setHidden(backdrop, true);
  setHidden(panel, true);
  openTarget = null;
  onSaveCallback = null;
  onPreviewCallback = null;
  originalConfigJson = null;
  dirty = false;
  savedThisSession = false;
}

function commit() {
  if (!openTarget) return;
  if (previewTimer) {
    clearTimeout(previewTimer);
    previewTimer = null;
  }
  const panel = document.querySelector(`[${ATTR_PANEL}]`);
  const newConfig = readBack(panel);
  // The board's _scheduleSave (50ms-debounced) handles persistence:
  // the onSave callback below re-renders the widget AND posts the
  // whole layout array (containing this widget's now-updated config)
  // to /dashboards/updateSettings. Per DD-05 the configure-form save
  // is independent of edit-mode layout saves.
  openTarget.setAttribute(ATTR_WIDGET_CONFIG, JSON.stringify(newConfig));
  savedThisSession = true;
  const target = openTarget;
  const cb = onSaveCallback;
  closeConfigure();
  if (cb) cb(target);
}

/**
 * Live-preview tick. Reads current form state, writes it into the
 * widget element's data-widget-config (so a subsequent render picks
 * it up), and invokes the onPreview callback so the board can
 * re-render the widget body. Fired by the debounced input/change
 * listener on the panel body.
 */
function firePreview() {
  previewTimer = null;
  if (!openTarget) return;
  const panel = document.querySelector(`[${ATTR_PANEL}]`);
  if (!panel) return;
  const newConfig = readBack(panel);
  openTarget.setAttribute(ATTR_WIDGET_CONFIG, JSON.stringify(newConfig));
  if (onPreviewCallback) onPreviewCallback(openTarget);
}

function schedulePreview() {
  dirty = true;
  if (previewTimer) clearTimeout(previewTimer);
  previewTimer = setTimeout(firePreview, PREVIEW_DEBOUNCE_MS);
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

  // KV-list add/remove buttons. Both also count as "dirty" edits so
  // the cancel path can revert the change.
  root.addEventListener('click', (e) => {
    const trigger = e.target.closest(`[${ATTR_KV_ACTION}]`);
    if (!trigger) return;
    const action = trigger.getAttribute(ATTR_KV_ACTION);
    if (action === 'add') {
      e.preventDefault();
      const list = root.querySelector('.misp-kv-list');
      list.appendChild(buildKVRow('', ''));
      list.lastElementChild.querySelector('.misp-kv-key').focus();
      // Adding an empty row alone doesn't change the config (empty
      // keys are skipped on readBack); typing into it will trigger
      // schedulePreview via the input listener below.
    } else if (action === 'remove') {
      e.preventDefault();
      trigger.closest('.misp-kv-row')?.remove();
      // Removing a populated row IS a config change — schedule a
      // preview tick so the user sees the effect immediately.
      schedulePreview();
    }
  });

  // Live preview (DD-06): every input/change inside the panel body
  // schedules a debounced re-render of the widget. Listener lives on
  // the body container so it survives body.replaceChildren() across
  // successive openConfigure calls. Click events from buttons inside
  // the form (preset shortcut buttons in the time_window picker,
  // KV add/remove) are handled above; the input/change listener
  // here fires when the user types into a text field, toggles a
  // checkbox, picks an enum option, etc.
  const bodyEl = root.querySelector(`[${ATTR_BODY}]`);
  if (bodyEl) {
    bodyEl.addEventListener('input', () => {
      if (openTarget) schedulePreview();
    });
    bodyEl.addEventListener('change', () => {
      if (openTarget) schedulePreview();
    });
  }

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
