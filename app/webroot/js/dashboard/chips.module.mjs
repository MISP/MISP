// Chip input — reusable component for editing arrays of short values.
//
// Used by:
//   - the configure form's bottom-tier KV list, when a row's value is
//     a JSON-encoded array — chips replace the raw text input so the
//     user doesn't have to hand-edit JSON brackets / quotes.
//   - Phase 3 canonical pickers (tag_filter, org_filter, …) that take
//     include/exclude lists of names.
//
// Behavior:
//   - Type into the inner <input> and press Enter, Tab, or comma to
//     commit a chip. Whitespace-only text is ignored. Pasting a
//     comma-separated string commits each token as a separate chip.
//   - Click × on a chip to remove it.
//   - Backspace on an empty input removes the last chip.
//   - Duplicates are silently de-duplicated.
//   - Every committed mutation dispatches a bubbling `input` event on
//     the root so the configure form's debounced live-preview reacts.
//   - Pending typed text is committed on blur so a click-to-Save
//     doesn't lose work.
//
// Type preservation: each chip carries the original value's runtime
// type (number / boolean / string) so a no-edit-touch round-trip
// stays lossless — `{local: [0,1]}` opened and saved untouched comes
// back as `{local: [0,1]}`, not `{local: ["0","1"]}`. Chips typed by
// the user default to string; no auto-coercion to number/bool (a tag
// literally named "123" must stay a string).

export const ATTR_ROOT   = 'data-misp-chips';
export const ATTR_REMOVE = 'data-misp-chip-remove';
export const ATTR_VALUE  = 'data-misp-chip-value';
export const ATTR_TYPE   = 'data-misp-chip-type';

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (v !== null && v !== undefined && v !== false) {
      node.setAttribute(k, v === true ? '' : String(v));
    }
  }
  for (const c of children) {
    if (c == null) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function buildChipNode(value) {
  const text = String(value);
  const attrs = { class: 'misp-chip', [ATTR_VALUE]: text };
  const t = typeof value;
  if (t === 'number' && Number.isFinite(value)) attrs[ATTR_TYPE] = 'number';
  else if (t === 'boolean') attrs[ATTR_TYPE] = 'boolean';
  return el('li', attrs,
    el('span', { class: 'misp-chip-label', text }),
    el('button', {
      type: 'button',
      class: 'misp-chip-remove',
      [ATTR_REMOVE]: '',
      title: 'Remove',
      'aria-label': `Remove ${text}`,
      text: '×',
    }),
  );
}

function chipsPresent(listEl) {
  return new Set(
    Array.from(listEl.querySelectorAll('.misp-chip'))
      .map(li => li.getAttribute(ATTR_VALUE))
  );
}

/**
 * Build a chip-input control.
 *
 * @param {Array|undefined|null} values - initial chip values. Non-
 *        string entries preserve their type via data attributes on the
 *        chip node so the round-trip is lossless.
 * @param {object} [opts]
 *   - placeholder: input placeholder (default 'Add and press Enter').
 *   - ariaLabel:  inner-input aria-label (defaults to placeholder).
 *   - schemaKey:  when wired to the configure form, set data-schema-
 *                 key on the root so the readback can find it.
 *   - dataType:   data-type marker (default 'array'). Paired with
 *                 schemaKey for configure-form readback dispatch.
 *   - rootClass:  extra class(es) on the root container.
 * @returns {HTMLElement} root container element.
 */
export function buildChips(values, opts = {}) {
  const placeholder = opts.placeholder || 'Add and press Enter';
  const initial = Array.isArray(values) ? values : [];
  const seen = new Set();
  const dedup = [];
  for (const v of initial) {
    const k = String(v);
    if (seen.has(k)) continue;
    seen.add(k);
    dedup.push(v);
  }
  const list = el('ul', { class: 'misp-chips-list' });
  for (const v of dedup) list.appendChild(buildChipNode(v));
  const input = el('input', {
    type: 'text',
    class: 'misp-chips-input',
    placeholder,
    'aria-label': opts.ariaLabel || placeholder,
  });
  const rootAttrs = {
    class: 'misp-chips' + (opts.rootClass ? ' ' + opts.rootClass : ''),
    [ATTR_ROOT]: '',
  };
  if (opts.schemaKey) {
    rootAttrs['data-schema-key'] = opts.schemaKey;
    rootAttrs['data-type'] = opts.dataType || 'array';
  }
  const root = el('div', rootAttrs, list, input);

  function notifyChange() {
    root.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function commitInput() {
    const raw = input.value;
    if (!raw || !raw.trim()) return false;
    const parts = raw.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length === 0) return false;
    const present = chipsPresent(list);
    let added = false;
    for (const p of parts) {
      if (present.has(p)) continue;
      present.add(p);
      list.appendChild(buildChipNode(p));
      added = true;
    }
    input.value = '';
    return added;
  }

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      if (!input.value.trim()) {
        if (e.key === 'Enter') e.preventDefault();
        return;
      }
      e.preventDefault();
      if (commitInput()) notifyChange();
    } else if (e.key === 'Tab' && input.value.trim()) {
      // Tab also commits, but only when there's content — preserve
      // natural focus traversal when the input is empty.
      e.preventDefault();
      if (commitInput()) notifyChange();
    } else if (e.key === 'Backspace' && input.value === '') {
      const last = list.lastElementChild;
      if (last) {
        last.remove();
        notifyChange();
      }
    }
  });

  // Remove-button delegation on the root.
  root.addEventListener('click', (e) => {
    const btn = e.target.closest('[' + ATTR_REMOVE + ']');
    if (!btn) return;
    e.preventDefault();
    const chip = btn.closest('.misp-chip');
    if (!chip) return;
    chip.remove();
    notifyChange();
  });

  // Clicking anywhere in the chip area focuses the input, so the
  // control feels like one cohesive surface.
  list.addEventListener('click', (e) => {
    if (e.target.closest('[' + ATTR_REMOVE + ']')) return;
    input.focus();
  });

  // Don't lose typed-but-uncommitted text on blur.
  input.addEventListener('blur', () => {
    if (commitInput()) notifyChange();
  });

  return root;
}

/**
 * Read the current chip array from a chip-input root element.
 * Preserves number / boolean types when those were the original input
 * types; otherwise returns strings. Order is DOM order.
 */
export function getChipsValue(rootEl) {
  if (!rootEl) return [];
  return Array.from(rootEl.querySelectorAll('.misp-chip')).map(chip => {
    const raw = chip.getAttribute(ATTR_VALUE) || '';
    const t = chip.getAttribute(ATTR_TYPE);
    if (t === 'number') {
      const n = Number(raw);
      return Number.isFinite(n) ? n : raw;
    }
    if (t === 'boolean') return raw === 'true';
    return raw;
  });
}
