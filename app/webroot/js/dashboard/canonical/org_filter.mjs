// `org_filter` canonical type (PRD §5.5 — refined naming).
//
// Wire shape:
//   { orgs: [{ uuid?, id?, name?, negate? }],
//     match_via: "orgc" | "sharing_group" | "any" }
//
// Picker UX (matches the canonical's two-axis structure):
//   - match_via dropdown — three options:
//       orgc          (events created by these orgs — Event.orgc_id)
//       sharing_group (events shared via these orgs' SG membership)
//       any           (either of the above)
//   - typeahead search input — fetches matching orgs from
//     /dashboards/searchOrganisations as the user types (debounced).
//   - suggestion list — clickable rows, click adds the org as a chip.
//   - chip list — selected orgs; clicking the chip toggles negate
//     state (visual + class change); × button removes the chip.
//
// Why typeahead vs flat list: production MISPs can carry 1000s of orgs;
// loading the full catalogue per picker-open burns bandwidth and
// scrolling becomes unusable past a few hundred entries. Server-side
// search keeps the surface tiny regardless of scale (per the picker UX
// decision tree from the prior session's Lesson #2: catalogue size,
// not feature complexity, governs picker shape).

export const KEY = 'org_filter';
export const LABEL = 'Organisations';

const MATCH_VIA_OPTIONS = [
  { value: 'orgc',          label: 'Created by (orgc)' },
  { value: 'sharing_group', label: 'Shared with via SG' },
  { value: 'any',           label: 'Any relationship' },
];

// No persistent catalogue cache — each query is parameterised and
// the result set is server-side-limited to 50 entries.
async function searchOrgs(q) {
  const url = '/dashboards/searchOrganisations.json'
    + '?q=' + encodeURIComponent(q || '');
  try {
    const r = await fetch(url, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    return r.ok ? await r.json() : [];
  } catch (_e) {
    return [];
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

function normaliseOrgsList(orgs) {
  if (!Array.isArray(orgs)) return [];
  const out = [];
  const seen = new Set();
  for (const entry of orgs) {
    if (!entry || typeof entry !== 'object') continue;
    const key = (entry.uuid || (entry.id != null ? `id:${entry.id}` : (entry.name || '')));
    if (key === '' || seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
  }
  return out;
}

function entryIdentityKey(entry) {
  if (entry.uuid) return `uuid:${entry.uuid}`;
  if (entry.id != null) return `id:${entry.id}`;
  if (entry.name) return `name:${entry.name}`;
  return '';
}

function entryDisplayName(entry) {
  return entry.name || entry.uuid || (entry.id != null ? `#${entry.id}` : '?');
}

/**
 * Order-insensitive structural equality.
 */
export function equal(a, b) {
  const ao = normaliseOrgsList(a?.orgs);
  const bo = normaliseOrgsList(b?.orgs);
  if (ao.length !== bo.length) return false;
  if ((a?.match_via || 'any') !== (b?.match_via || 'any')) return false;
  const aKeys = ao.map((e) => entryIdentityKey(e) + (e.negate ? '!' : '')).sort();
  const bKeys = bo.map((e) => entryIdentityKey(e) + (e.negate ? '!' : '')).sort();
  for (let i = 0; i < aKeys.length; i++) if (aKeys[i] !== bKeys[i]) return false;
  return true;
}

/**
 * Compact display label for the toolbar chip.
 *
 *   null / undefined        → "(unset)"
 *   { orgs: [] }             → "(none)"
 *   { orgs: [3 entries] }    → "+3"
 */
export function displayLabel(value) {
  if (value == null) return '(unset)';
  const arr = normaliseOrgsList(value?.orgs);
  if (arr.length === 0) return '(none)';
  return `+${arr.length}`;
}

/**
 * Build the org_filter picker.
 *
 * @param {object|null|undefined} currentValue
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const initial = (currentValue && typeof currentValue === 'object' && !Array.isArray(currentValue))
    ? currentValue : {};
  const initialOrgs = normaliseOrgsList(initial.orgs);
  const initialMatchVia = (typeof initial.match_via === 'string'
                          && MATCH_VIA_OPTIONS.some((o) => o.value === initial.match_via))
    ? initial.match_via : 'any';

  // --- DOM scaffolding ---
  const matchViaSelect = el('select', {
    class: 'misp-org-filter-match-via',
    'aria-label': 'Match via',
  });
  MATCH_VIA_OPTIONS.forEach((o) => {
    matchViaSelect.appendChild(el('option', {
      value: o.value,
      text: o.label,
      selected: o.value === initialMatchVia ? true : false,
    }));
  });

  const searchInput = el('input', {
    type: 'search',
    class: 'misp-org-filter-search',
    placeholder: 'Search organisations…',
    'aria-label': 'Search organisations',
  });

  const suggestionList = el('div', {
    class: 'misp-org-filter-suggestions',
    role: 'listbox',
    'aria-label': 'Organisation suggestions',
  });

  const chipList = el('div', {
    class: 'misp-org-filter-chips',
    role: 'group',
    'aria-label': 'Selected organisations',
  });
  initialOrgs.forEach((entry) => chipList.appendChild(buildChip(entry)));

  const helpText = 'Filter events by organisation. Pick match style, search by name, and click suggestions to add. Click a chip to toggle exclude (!) state.';
  const canonicalHelp = 'Canonical type — bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.';

  const root = el('div', {
    class: 'misp-field misp-org-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    el('div', { class: 'misp-org-filter-row' }, matchViaSelect, searchInput),
    suggestionList,
    chipList,
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? helpText : `${helpText} ${canonicalHelp}`,
    }),
  );

  function buildChip(entry) {
    const isNegated = !!entry.negate;
    const label = entryDisplayName(entry);
    const chip = el('span', {
      class: 'misp-org-filter-chip' + (isNegated ? ' misp-org-filter-chip--negated' : ''),
      'data-identity-key': entryIdentityKey(entry),
      'data-uuid': entry.uuid || '',
      'data-id':   entry.id != null ? String(entry.id) : '',
      'data-name': entry.name || '',
      'data-negate': isNegated ? '1' : '0',
      title: `${isNegated ? 'Excluding' : 'Including'} ${label}`,
    });
    const labelSpan = el('button', {
      type: 'button',
      class: 'misp-org-filter-chip-label',
      'aria-label': `Toggle exclude for ${label}`,
      text: (isNegated ? '!' : '') + label,
      onclick: () => {
        const neg = chip.getAttribute('data-negate') === '1';
        chip.setAttribute('data-negate', neg ? '0' : '1');
        chip.classList.toggle('misp-org-filter-chip--negated', !neg);
        labelSpan.textContent = (!neg ? '!' : '') + label;
        chip.title = `${!neg ? 'Excluding' : 'Including'} ${label}`;
        root.dispatchEvent(new Event('change', { bubbles: true }));
      },
    });
    const removeBtn = el('button', {
      type: 'button',
      class: 'misp-org-filter-chip-remove',
      'aria-label': `Remove ${label}`,
      onclick: () => {
        chip.remove();
        root.dispatchEvent(new Event('change', { bubbles: true }));
      },
    }, '×');
    chip.append(labelSpan, removeBtn);
    return chip;
  }

  function currentChipKeys() {
    return new Set(Array.from(chipList.querySelectorAll('[data-identity-key]'))
      .map((c) => c.getAttribute('data-identity-key')));
  }

  function addOrg(entry) {
    const key = entryIdentityKey(entry);
    if (!key) return;
    if (currentChipKeys().has(key)) return;
    chipList.appendChild(buildChip(entry));
  }

  function renderSuggestions(orgs) {
    if (!Array.isArray(orgs) || orgs.length === 0) {
      suggestionList.replaceChildren(el('div', {
        class: 'misp-org-filter-suggestions-empty',
        text: 'No matches.',
      }));
      return;
    }
    const selected = currentChipKeys();
    const rows = orgs.map((o) => {
      const entry = {};
      if (o.uuid) entry.uuid = String(o.uuid);
      if (o.id != null) entry.id = parseInt(o.id, 10);
      if (o.name) entry.name = String(o.name);
      const isSelected = selected.has(entryIdentityKey(entry));
      const sub = o.uuid || (o.id != null ? `#${o.id}` : '');
      const row = el('button', {
        type: 'button',
        class: 'misp-org-filter-suggestion' + (isSelected ? ' misp-org-filter-suggestion--selected' : ''),
        title: sub || entry.name || '',
        onclick: () => {
          addOrg(entry);
          row.classList.add('misp-org-filter-suggestion--selected');
          root.dispatchEvent(new Event('change', { bubbles: true }));
        },
      },
        el('span', { class: 'misp-org-filter-suggestion-name', text: entry.name || sub }),
        sub && entry.name ? el('span', { class: 'misp-org-filter-suggestion-sub', text: sub }) : null,
      );
      return row;
    });
    suggestionList.replaceChildren(...rows);
  }

  // Debounced search.
  let searchTimer = null;
  function scheduleSearch() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
      const orgs = await searchOrgs(searchInput.value);
      renderSuggestions(orgs);
    }, 250);
  }
  searchInput.addEventListener('input', scheduleSearch);
  matchViaSelect.addEventListener('change', () => {
    root.dispatchEvent(new Event('change', { bubbles: true }));
  });

  return root;
}

/**
 * Read the current org_filter value from a picker root.
 *
 * Returns the structured shape:
 *   { orgs: [{ uuid?, id?, name?, negate? }], match_via: <enum> }
 *
 * Orgs are emitted in chip-list DOM order (stable, user-visible).
 */
export function readValue(rootEl) {
  if (!rootEl) return { orgs: [], match_via: 'any' };
  const chips = rootEl.querySelectorAll('.misp-org-filter-chips [data-identity-key]');
  const orgs = Array.from(chips).map((c) => {
    const entry = {};
    const uuid = c.getAttribute('data-uuid');
    const id   = c.getAttribute('data-id');
    const name = c.getAttribute('data-name');
    if (uuid) entry.uuid = uuid;
    if (id !== '' && id !== null) entry.id = parseInt(id, 10);
    if (name) entry.name = name;
    if (c.getAttribute('data-negate') === '1') entry.negate = true;
    return entry;
  });
  const mv = rootEl.querySelector('.misp-org-filter-match-via');
  const match_via = mv ? mv.value : 'any';
  return { orgs, match_via };
}
