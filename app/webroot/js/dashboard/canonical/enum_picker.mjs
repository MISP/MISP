// Shared factory for int-enum-array canonical pickers.
//
// `distribution_filter`, `threat_level_filter`, and `analysis_filter`
// all render as a row of toggle buttons over a small fixed set of
// integer levels. The picker's behaviour is identical across the
// three; only the level vocabulary + the (currently per-module) CSS
// class namespace differ. Extracted on the third copy (analysis_filter)
// per "three similar lines forces a refactor".
//
// Server-side counterpart: `CanonicalTypeAdapter::_normaliseIntArray`.
// The two extractions track each other — adding a 4th int-enum
// canonical means adding both a translator (one line) and a picker
// module (one factory call).
//
// The factory returns a full module surface: KEY / LABEL / LEVELS /
// equal / displayLabel / buildField / readValue. Each per-canonical
// module is then a thin shell:
//
//   import { makeEnumPicker } from './enum_picker.mjs';
//   const picker = makeEnumPicker({ key, label, levels, ... });
//   export const { KEY, LABEL, LEVELS, equal, displayLabel,
//                  buildField, readValue } = picker;
//
// Toolbar integration (CANONICAL_REGISTRY) and configure form
// integration (CANONICAL_BUILDERS) consume the same surface; the
// factory parameterises everything that varies.

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
 * Build an int-enum picker module.
 *
 * @param {object} opts
 * @param {string} opts.key            Canonical type name (e.g. 'distribution_filter').
 *                                      Used as the data-canonical / data-type
 *                                      attribute and as the default schema key.
 * @param {string} opts.label          Display label (e.g. 'Distribution').
 * @param {Array<{value:number, label:string, hint?:string}>} opts.levels
 *                                      The enum's valid values.
 * @param {string} opts.valueAttr      Per-toggle data-* attribute name carrying
 *                                      the level value (e.g. 'data-distribution-level').
 *                                      Used by readValue's querySelector.
 * @param {string} opts.rootClass      CSS class for the picker root div
 *                                      (e.g. 'misp-distribution-filter').
 * @param {string} opts.togglesClass   CSS class for the inner toggle row container
 *                                      (e.g. 'misp-distribution-toggles').
 * @param {string} opts.toggleClass    CSS class for each toggle button
 *                                      (e.g. 'misp-distribution-toggle').
 * @param {string} opts.helpText       Help text shown next to the field
 *                                      (e.g. 'Filter events by distribution level.
 *                                      Empty selection = no filter ...').
 * @returns {{
 *   KEY: string, LABEL: string, LEVELS: Array,
 *   equal: (a:any, b:any) => boolean,
 *   displayLabel: (v:any) => string,
 *   buildField: (v:any, opts?:object) => HTMLElement,
 *   readValue: (root:HTMLElement|null) => number[]
 * }}
 */
export function makeEnumPicker(opts) {
  const { key, label, levels, valueAttr, rootClass, togglesClass, toggleClass, helpText } = opts;
  const validValues = new Set(levels.map((l) => l.value));

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
   * Order-insensitive equality. [1,2] vs [2,1] read as equal so the
   * toolbar's mixed-state detection doesn't false-positive when two
   * widgets store the same set in a different order.
   */
  function equal(a, b) {
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
   * Compact toolbar chip label:
   *   []        → "(all)"   no filter applied
   *   [v1..vN]  → "(all)"   full selection = effectively no filter
   *   [v]       → level label (e.g. "High", "Org only")
   *   [v,w,…]   → "N levels"
   */
  function displayLabel(value) {
    const arr = toIntArray(value);
    if (arr.length === 0 || arr.length === levels.length) return '(all)';
    if (arr.length === 1) {
      const level = levels.find((l) => l.value === arr[0]);
      return level ? level.label : `Level ${arr[0]}`;
    }
    return `${arr.length} levels`;
  }

  /**
   * Build the picker DOM. Toggle row over the levels; aria-pressed
   * is the source of truth (no hidden inputs).
   *
   * Each toggle dispatches a bubbling `change` event on the root so
   * the configure module's debounced live-preview listener fires.
   */
  function buildField(currentValue, optsArg = {}) {
    const schemaKey = optsArg.schemaKey || key;
    const selected = new Set(toIntArray(currentValue));

    let root;
    const toggles = levels.map((level) => {
      const pressed = selected.has(level.value);
      const btn = el('button', {
        type: 'button',
        class: toggleClass,
        [valueAttr]: String(level.value),
        'aria-pressed': pressed ? 'true' : 'false',
        title: level.hint || level.label,
        onclick: (e) => {
          e.preventDefault();
          const isPressed = btn.getAttribute('aria-pressed') === 'true';
          btn.setAttribute('aria-pressed', isPressed ? 'false' : 'true');
          root.dispatchEvent(new Event('change', { bubbles: true }));
        },
      }, level.label);
      return btn;
    });

    const canonicalHelp = 'Canonical type — Phase 3 toolbar bulk-edits this across every widget that declares it.';

    root = el('div', {
      class: `misp-field ${rootClass}`,
      'data-canonical': key,
      'data-schema-key': schemaKey,
      'data-type': key,
    },
      el('span', { class: 'misp-field-label', text: label }),
      el('div', { class: togglesClass }, ...toggles),
      el('span', {
        class: 'misp-field-help',
        text: optsArg.compact ? helpText : `${helpText} ${canonicalHelp}`,
      }),
    );
    return root;
  }

  /**
   * Read the picker's current value as an int array. Dispatched by
   * configure.module.mjs's readBack via CANONICAL_BUILDERS, and by
   * toolbar.module.mjs's commitBulk / computeState via CANONICAL_REGISTRY.
   */
  function readValue(rootEl) {
    if (!rootEl) return [];
    const out = [];
    const sel = `[${valueAttr}][aria-pressed="true"]`;
    for (const btn of rootEl.querySelectorAll(sel)) {
      const n = parseInt(btn.getAttribute(valueAttr), 10);
      if (Number.isFinite(n) && validValues.has(n)) out.push(n);
    }
    return out;
  }

  return {
    KEY: key,
    LABEL: label,
    LEVELS: levels,
    equal,
    displayLabel,
    buildField,
    readValue,
  };
}
