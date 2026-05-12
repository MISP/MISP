// dashboard-v2 — `time_window` canonical type (PRD §5.5).
//
// Shared between the configure form (per-widget edit) and the
// dashboard toolbar (bulk edit, DD-05). Each canonical type lives in
// its own module under `canonical/` so a Phase 3 sweep can add new
// pickers without growing a monolith.
//
// Wire format stays in the legacy `<N>d` shape (or integer seconds,
// or `-1` sentinel) so unmodified widgets parse it. Phase 2's
// canonical→legacy adapter swaps the wire to ISO 8601 once it lands.

export const KEY = 'time_window';
export const LABEL = 'Time window';

// Shortcut buttons. The input itself is the source of truth.
export const PRESETS = [
  { value: '1d',  label: '24h' },
  { value: '7d',  label: '7d' },
  { value: '30d', label: '30d' },
  { value: '90d', label: '90d' },
  { value: '-1',  label: 'All' },
];

// Compact display for the toolbar chip — maps a saved wire value back
// to a human label when possible. Custom values render as-is (e.g.
// "14d" stays "14d") so the chip remains informative.
export function displayLabel(value) {
  if (value == null || value === '') return '(unset)';
  const v = String(value);
  switch (v) {
    case '1d':  return '24h';
    case '7d':  return '7d';
    case '30d': return '30d';
    case '90d': return '90d';
    case '-1':  return 'All time';
    default:    return v;
  }
}

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
 * Build the time_window field. Single text input (source of truth)
 * + preset shortcut buttons + format hint. The input carries the
 * `data-canonical="time_window"` hook so generic readback code (the
 * configure form, the toolbar popover) finds it without knowing the
 * type by name.
 *
 * @param {string|number|undefined} currentValue
 * @param {{compact?: boolean}} [opts] - compact omits the help text
 *        for tight surfaces like the toolbar popover.
 */
export function buildField(currentValue, opts = {}) {
  const value = currentValue == null ? '' : String(currentValue);
  const input = el('input', {
    type: 'text',
    class: 'misp-field-input',
    'data-canonical': KEY,
    value,
    placeholder: 'e.g. 7d, 86400, -1',
    'aria-label': LABEL,
  });

  const presets = el('div', { class: 'misp-time-window-presets' });
  function syncActive() {
    const v = input.value;
    for (const b of presets.children) {
      b.classList.toggle('is-active', b.getAttribute('data-preset') === v);
    }
  }
  for (const p of PRESETS) {
    const btn = el('button', {
      type: 'button',
      class: 'misp-dashboard-btn misp-time-window-preset',
      'data-preset': p.value,
      text: p.label,
      onclick: () => {
        input.value = p.value;
        syncActive();
        input.dispatchEvent(new Event('change', { bubbles: true }));
      },
    });
    presets.appendChild(btn);
  }
  input.addEventListener('input', syncActive);
  Promise.resolve().then(syncActive);

  // Format hint always present so users see the supported grammar
  // without leaving the popover. The "canonical type" tail is
  // contextual to the configure form (toolbar already implies it)
  // so we drop it in compact mode.
  const formatHelp = 'Use Nd for days (e.g. 14d), an integer for seconds, or -1 for all time.';
  const canonicalHelp = 'Canonical type — the dashboard toolbar bulk-edits this across every widget that declares it.';
  return el('label', { class: 'misp-field' },
    el('span', { class: 'misp-field-label', text: LABEL }),
    input,
    presets,
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? formatHelp : `${formatHelp} ${canonicalHelp}`,
    }),
  );
}
