// `sharing_group_filter` canonical type (PRD §5.5).
//
// Used by the schema-driven configure form's typed-fields tier and the
// toolbar's per-canonical chip popover. Wire shape is an int array of
// SharingGroup.id values — same vocabulary as the int-enum canonicals
// (distribution / threat_level / analysis) — but the valid set is NOT
// a fixed enum: accessible SG IDs depend on the current user's role
// and membership, determined at request time.
//
// That property forces a different picker shape from the
// enum_picker factory:
//
//   - Int-enum canonicals (distribution / threat_level / analysis):
//     4-6 fixed levels, rendered as toggle-button rows. The factory
//     embeds the level vocabulary statically. Picker renders
//     synchronously.
//
//   - sharing_group_filter: N=O(SG count) dynamic options, queried
//     from /dashboards/listSharingGroups.json. Picker renders
//     asynchronously (Loading… → list once the fetch resolves).
//     Module-level promise cache makes second + opens instant.
//
// Picker UX: search input + scrollable checkbox list of all
// accessible SGs (sorted by name). Selected SGs stay visible
// regardless of the search filter so the user can always see what
// they've chosen. Search filters the unselected list by case-
// insensitive substring on the SG name.

export const KEY = 'sharing_group_filter';
export const LABEL = 'Sharing group';

// Module-level cache so opening the configure form a second time on
// the same page doesn't re-fetch. Cleared by reloading the page —
// that's the natural invalidation window since SG membership rarely
// changes within a single dashboard session.
let _sgListPromise = null;

function loadSgList() {
  if (_sgListPromise) return _sgListPromise;
  _sgListPromise = fetch('/dashboards/listSharingGroups.json', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  })
    .then((r) => (r.ok ? r.json() : []))
    .catch(() => []);
  return _sgListPromise;
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
 * Order-insensitive equality. [1,5] vs [5,1] read as equal so the
 * toolbar's mixed-state detection doesn't flicker on order
 * differences across declarers.
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
 *
 *   undefined / null → "(unset)"
 *   []               → "(none)"
 *   [1]              → "+1"
 *   [1,5,12]         → "+3"
 */
export function displayLabel(value) {
  if (value == null) return '(unset)';
  const arr = toIntArray(value);
  if (arr.length === 0) return '(none)';
  return `+${arr.length}`;
}

/**
 * Build the sharing_group_filter picker.
 *
 * The picker renders a Loading placeholder synchronously, then swaps
 * in the actual checkbox list once `/dashboards/listSharingGroups`
 * resolves. The selected IDs in `currentValue` are honoured both
 * before and after the swap — readValue scans the rendered checkbox
 * state, and on resolve the unselected entries appear with their
 * names while the selected entries keep their checkmark.
 *
 * @param {number[]|number|string|null|undefined} currentValue
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const selected = new Set(toIntArray(currentValue));

  const searchInput = el('input', {
    type: 'search',
    class: 'misp-sg-filter-search',
    placeholder: 'Search sharing groups…',
    'aria-label': 'Search sharing groups',
  });

  const listContainer = el('div', {
    class: 'misp-sg-filter-list',
    role: 'group',
    'aria-label': 'Sharing group options',
  });
  listContainer.appendChild(el('div', {
    class: 'misp-sg-filter-loading',
    text: 'Loading sharing groups…',
  }));

  const helpText = 'Filter events by sharing group. Empty selection = no filter; selecting multiple groups returns events shared via any of them.';
  const canonicalHelp = 'Canonical type — bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.';

  const root = el('div', {
    class: 'misp-field misp-sg-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    searchInput,
    listContainer,
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? helpText : `${helpText} ${canonicalHelp}`,
    }),
  );

  // Wire search filter — debouncing not necessary at this scale (an
  // average instance has tens of SGs, exceptionally a few hundred).
  searchInput.addEventListener('input', () => {
    const q = searchInput.value.trim().toLowerCase();
    const rows = listContainer.querySelectorAll('.misp-sg-filter-row');
    rows.forEach((row) => {
      // Selected rows stay visible regardless of the search filter so
      // the user can always see (and uncheck) what they've chosen.
      const isSelected = row.querySelector('input[type=checkbox]')?.checked;
      if (isSelected) {
        row.style.display = '';
        return;
      }
      const name = (row.getAttribute('data-sg-name') || '').toLowerCase();
      row.style.display = !q || name.includes(q) ? '' : 'none';
    });
  });

  // Async-fill the list once the SG catalogue resolves.
  loadSgList().then((sgs) => {
    if (!Array.isArray(sgs) || sgs.length === 0) {
      listContainer.replaceChildren(el('div', {
        class: 'misp-sg-filter-empty',
        text: 'No sharing groups accessible.',
      }));
      return;
    }
    const rows = sgs.map((sg) => {
      const id = Number(sg.id) | 0;
      const name = String(sg.name || `SG #${id}`);
      const checked = selected.has(id);
      const row = el('label', {
        class: 'misp-sg-filter-row',
        'data-sg-id': id,
        'data-sg-name': name,
      },
        el('input', {
          type: 'checkbox',
          'data-sg-id': id,
          checked: checked || null,
        }),
        el('span', { class: 'misp-sg-filter-name', text: name }),
      );
      return row;
    });
    listContainer.replaceChildren(...rows);
  });

  return root;
}

/**
 * Read the current sharing_group_filter value from a picker root
 * element. Dispatched by configure.module.mjs's readBack and
 * toolbar.module.mjs's commitBulk via the canonical registries.
 *
 * Returns an int[] sorted ascending for deterministic equality on
 * round-trip. Empty array = no filter.
 *
 * Edge case: if the picker is read back BEFORE the async list has
 * resolved, no checkboxes exist yet → returns []. The configure
 * form's save flow generally waits for user interaction, so this
 * race is unlikely in practice; the toolbar's bulk-edit dispatch
 * reads picker state after the user clicks "Apply" which presumes
 * the picker has been visible long enough for the fetch to resolve.
 */
export function readValue(rootEl) {
  if (!rootEl) return [];
  const inputs = rootEl.querySelectorAll('input[type=checkbox][data-sg-id]');
  const out = [];
  inputs.forEach((cb) => {
    if (!cb.checked) return;
    const id = Number(cb.getAttribute('data-sg-id'));
    if (Number.isFinite(id)) out.push(id | 0);
  });
  return out.sort((a, b) => a - b);
}
