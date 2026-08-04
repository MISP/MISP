// `galaxy_cluster_filter` canonical type (PRD §5.5).
//
// Two-axis canonical: filter events by specific galaxy cluster tag
// names, optionally scoped to a set of galaxy types for picker
// browsing. Wire shape:
//
//   { tag_names:   string[],   // the actual filter
//     galaxy_types?: string[] } // picker scope hint
//
// The picker's UX is genuinely different from the other canonicals
// because of the catalogue scale (55k clusters across 121 galaxy
// types on the test instance):
//
//   - Int-enum canonicals (distribution / threat_level / analysis):
//     toggle-button rows over a 4-6 fixed levels. Synchronous.
//
//   - sharing_group_filter: scrollable checkbox list of ALL accessible
//     SGs (typically <500). Async-loaded but single fetch.
//
//   - galaxy_cluster_filter: typeahead-style search. Galaxy types
//     loaded once via /dashboards/listGalaxyTypes; user picks a type
//     (dropdown); cluster search via /dashboards/searchGalaxyClusters
//     debounced ~250ms as user types into the search input.
//     Selected clusters render as chips below.
//
// Selected clusters survive galaxy-type changes — the chip list is
// the source of truth for `tag_names`, independent of the picker's
// current `galaxy_types` scope. Removing a chip removes the cluster
// from `tag_names`.

export const KEY = 'galaxy_cluster_filter';
export const LABEL = 'Galaxy cluster';

// Module-level cache for the galaxy-types catalogue (small, ~120
// entries — fetched once per page load).
let _galaxyTypesPromise = null;
function loadGalaxyTypes() {
  if (_galaxyTypesPromise) return _galaxyTypesPromise;
  _galaxyTypesPromise = fetch('/dashboards/listGalaxyTypes.json', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  })
    .then((r) => (r.ok ? r.json() : []))
    .catch(() => []);
  return _galaxyTypesPromise;
}

// No cache for cluster search — each query is parameterised and the
// result set changes with `q`. Caching the latest-active query is
// not worth the invalidation complexity at this scale.
async function searchClusters(galaxyType, q) {
  if (!galaxyType) return [];
  const url = '/dashboards/searchGalaxyClusters.json'
    + '?galaxy_type=' + encodeURIComponent(galaxyType)
    + '&q=' + encodeURIComponent(q || '');
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

function normaliseStringArray(v) {
  if (typeof v === 'string') return v === '' ? [] : [v];
  if (!Array.isArray(v)) return [];
  const seen = new Set();
  const out = [];
  for (const s of v) {
    if (typeof s !== 'string' || s === '') continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

/**
 * Order-insensitive equality on the structured wire shape.
 */
export function equal(a, b) {
  const aTags = normaliseStringArray(a?.tag_names);
  const bTags = normaliseStringArray(b?.tag_names);
  const aTypes = normaliseStringArray(a?.galaxy_types);
  const bTypes = normaliseStringArray(b?.galaxy_types);
  if (aTags.length !== bTags.length) return false;
  if (aTypes.length !== bTypes.length) return false;
  const sa = [...aTags].sort();
  const sb = [...bTags].sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  const sta = [...aTypes].sort();
  const stb = [...bTypes].sort();
  for (let i = 0; i < sta.length; i++) if (sta[i] !== stb[i]) return false;
  return true;
}

/**
 * Compact display label for the toolbar chip.
 *
 *   null / undefined          → "(unset)"
 *   { tag_names: [] }         → "(none)"
 *   { tag_names: [3 entries] }→ "+3"
 */
export function displayLabel(value) {
  if (value == null) return '(unset)';
  const arr = normaliseStringArray(value?.tag_names);
  if (arr.length === 0) return '(none)';
  return `+${arr.length}`;
}

/**
 * Extract the short label from a full cluster tag_name, for chip
 * display. The tag_name format is
 * `misp-galaxy:<type>="<value>"`; we strip the prefix so the
 * chip shows just the value (e.g. "Phishing - T1566") rather than
 * the full tag.
 */
function shortLabel(tagName) {
  const m = String(tagName).match(/^misp-galaxy:[^=]+="(.+)"$/);
  return m ? m[1] : String(tagName);
}

/**
 * Build the galaxy_cluster_filter picker.
 *
 * @param {object|null|undefined} currentValue
 * @param {{compact?: boolean, schemaKey?: string}} [opts]
 */
export function buildField(currentValue, opts = {}) {
  const schemaKey = opts.schemaKey || KEY;
  const initial = (currentValue && typeof currentValue === 'object' && !Array.isArray(currentValue))
    ? currentValue : {};
  // Source of truth for the picker's selected clusters and active
  // galaxy types is the DOM (chip list + checkbox state) — these
  // local references just seed the initial render.
  const initialTags = normaliseStringArray(initial.tag_names);
  const initialTypes = normaliseStringArray(initial.galaxy_types);
  // The current galaxy-type scope for the search input. Single-select
  // (the picker scopes to one type at a time for UI clarity); the
  // structured wire's `galaxy_types: string[]` is the union of types
  // the user has ever scoped to during this session — preserved
  // verbatim on read.
  let currentScope = initialTypes[0] || '';

  // --- DOM scaffolding ---
  const scopeSelect = el('select', {
    class: 'misp-gc-filter-scope',
    'aria-label': 'Galaxy type',
  });
  scopeSelect.appendChild(el('option', { value: '', text: '— pick a galaxy type —' }));

  const searchInput = el('input', {
    type: 'search',
    class: 'misp-gc-filter-search',
    placeholder: 'Search clusters…',
    'aria-label': 'Search clusters',
    disabled: true,
  });

  const suggestionList = el('div', {
    class: 'misp-gc-filter-suggestions',
    role: 'listbox',
    'aria-label': 'Cluster suggestions',
  });

  const chipList = el('div', {
    class: 'misp-gc-filter-chips',
    role: 'group',
    'aria-label': 'Selected clusters',
  });
  // Seed chips from initial tag_names.
  initialTags.forEach((tn) => chipList.appendChild(buildChip(tn)));

  const helpText = 'Filter events by galaxy cluster. Pick a galaxy type, then search for clusters; selected clusters appear as removable chips below.';
  const canonicalHelp = 'Canonical type — bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.';

  const root = el('div', {
    class: 'misp-field misp-gc-filter',
    'data-canonical': KEY,
    'data-schema-key': schemaKey,
    'data-type': KEY,
  },
    el('span', { class: 'misp-field-label', text: LABEL }),
    el('div', { class: 'misp-gc-filter-row' }, scopeSelect, searchInput),
    suggestionList,
    chipList,
    el('span', {
      class: 'misp-field-help',
      text: opts.compact ? helpText : `${helpText} ${canonicalHelp}`,
    }),
  );

  // Track every galaxy type the user has scoped to during this open
  // (for the canonical's galaxy_types axis on read). Seeded from
  // initial config.
  const visitedTypes = new Set(initialTypes);

  function buildChip(tagName) {
    const chip = el('span', {
      class: 'misp-gc-filter-chip',
      'data-tag-name': tagName,
      title: tagName,
    },
      el('span', { class: 'misp-gc-filter-chip-label', text: shortLabel(tagName) }),
    );
    const removeBtn = el('button', {
      type: 'button',
      class: 'misp-gc-filter-chip-remove',
      'aria-label': `Remove ${shortLabel(tagName)}`,
      onclick: () => chip.remove(),
    }, '×');
    chip.appendChild(removeBtn);
    return chip;
  }

  function currentSelectedTagNames() {
    return Array.from(chipList.querySelectorAll('[data-tag-name]'))
      .map((c) => c.getAttribute('data-tag-name'));
  }

  function addCluster(tagName) {
    // Idempotent — silently ignore duplicates.
    if (currentSelectedTagNames().includes(tagName)) return;
    chipList.appendChild(buildChip(tagName));
  }

  function renderSuggestions(clusters) {
    if (!Array.isArray(clusters) || clusters.length === 0) {
      suggestionList.replaceChildren(el('div', {
        class: 'misp-gc-filter-suggestions-empty',
        text: 'No matches.',
      }));
      return;
    }
    const selected = new Set(currentSelectedTagNames());
    const rows = clusters.map((c) => {
      const tagName = String(c.tag_name);
      const value = String(c.value || tagName);
      const isSelected = selected.has(tagName);
      const row = el('button', {
        type: 'button',
        class: 'misp-gc-filter-suggestion' + (isSelected ? ' misp-gc-filter-suggestion--selected' : ''),
        title: tagName,
        'data-tag-name': tagName,
        onclick: () => {
          addCluster(tagName);
          row.classList.add('misp-gc-filter-suggestion--selected');
          // Optionally fire change for live-preview hooks.
          root.dispatchEvent(new Event('change', { bubbles: true }));
        },
      }, value);
      return row;
    });
    suggestionList.replaceChildren(...rows);
  }

  // Debounced cluster search.
  let searchTimer = null;
  function scheduleSearch() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
      if (!currentScope) return;
      const clusters = await searchClusters(currentScope, searchInput.value);
      renderSuggestions(clusters);
    }, 250);
  }

  scopeSelect.addEventListener('change', () => {
    currentScope = scopeSelect.value || '';
    searchInput.disabled = !currentScope;
    if (currentScope) {
      visitedTypes.add(currentScope);
      // Eager search on scope change with the current `q` (empty
      // by default → first 50 clusters of the type).
      scheduleSearch();
    } else {
      suggestionList.replaceChildren();
    }
  });

  searchInput.addEventListener('input', scheduleSearch);

  // Async-fill the scope dropdown once the galaxy types catalogue
  // resolves.
  loadGalaxyTypes().then((types) => {
    if (!Array.isArray(types) || types.length === 0) {
      scopeSelect.appendChild(el('option', {
        value: '',
        disabled: true,
        text: 'No galaxy types available',
      }));
      return;
    }
    types.forEach((t) => {
      scopeSelect.appendChild(el('option', {
        value: t.type,
        text: `${t.name} (${t.cluster_count})`,
      }));
    });
    // Restore the initial scope if the config had one.
    if (currentScope) {
      scopeSelect.value = currentScope;
      searchInput.disabled = false;
      // Don't auto-search on initial restore — the user may not
      // intend to add more clusters right now. They can click into
      // the search input to trigger.
    }
  });

  // Stash visitedTypes on the root so readValue can re-emit
  // galaxy_types verbatim. Using a DOM property (rather than a
  // data-attr) avoids JSON serialisation overhead for what is just
  // a session-scoped state cache.
  root._mispGcVisitedTypes = visitedTypes;

  return root;
}

/**
 * Read the current galaxy_cluster_filter value from a picker root.
 *
 * Returns the structured shape:
 *   { tag_names: string[], galaxy_types: string[] }
 *
 * tag_names: sorted ascending for deterministic equality on round-
 * trip. galaxy_types: every type the user scoped to during this
 * picker session (including the initial config + any newly visited).
 */
export function readValue(rootEl) {
  if (!rootEl) return { tag_names: [], galaxy_types: [] };
  const chips = rootEl.querySelectorAll('.misp-gc-filter-chips [data-tag-name]');
  const tag_names = Array.from(chips)
    .map((c) => c.getAttribute('data-tag-name'))
    .filter((s) => typeof s === 'string' && s !== '')
    .sort();
  const visited = rootEl._mispGcVisitedTypes;
  const galaxy_types = visited instanceof Set ? Array.from(visited).sort() : [];
  return { tag_names, galaxy_types };
}
