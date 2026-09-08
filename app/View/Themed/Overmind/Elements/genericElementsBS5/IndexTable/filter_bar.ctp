<?php
App::uses('IndexFilterDraft', 'Tools');

$filter_bar = $scaffold_data['filter_bar'] ?? null;
if (empty($filter_bar)) {
    return;
}

// The action this bar drives — pagination/search/filter URLs are built against
// `<item_url>/<action>`. Defaults to 'index';
$filterAction = $filter_bar['action'] ?? 'index';

$currentPath = $this->request->here(false);
$currentFilters = [];

if (preg_match('~/' . preg_quote($filterAction, '~') . '/(.+)~', $currentPath, $matches)) {
    $segments = explode('/', $matches[1]);
    foreach ($segments as $segment) {
        if (strpos($segment, ':') !== false) {
            list($key, $value) = explode(':', $segment, 2);
            $cleanKey = preg_replace('/^search/', '', $key);
            $currentFilters[$cleanKey] = $value;
        }
    }
}

$transport = $filter_bar['transport'] ?? 'path';

if ($transport === 'query') {
    foreach (($this->request->query ?? []) as $queryKey => $queryValue) {
        if (is_string($queryValue) && $queryValue !== '') {
            $currentFilters[$queryKey] = $queryValue;
        }
    }
}

$hasActiveFilters = !empty($currentFilters);

$filterId = 'filter-bar-' . uniqid();

$searchChild = null;
foreach ($filter_bar['children'] as $child) {
    if ($child['type'] === 'search') {
        $searchChild = $child;
        break;
    }
}

/*
 * The advanced filters are pulled out of the bar's flex row: the button stays
 * in the row as a collapse toggle, the grid of controls and the summary that
 * runs them are rendered underneath it.
 */
$moreFiltersChild = null;
foreach ($filter_bar['children'] as $child) {
    if (($child['type'] ?? '') === 'more_filters') {
        $moreFiltersChild = $child;
        break;
    }
}

// Which URL params are *this bar's own controls* (removable) — everything else
// (e.g. searchemail: scope, positional pass-args) must never show as a
// removable chip and must survive "Clear all".
$controlKeys = [];
// Optional per-control `chip_label`, so a chip can read "Value: 8.8.8.8"
// instead of exposing the raw url key.
$controlLabels = [];
foreach (($filter_bar['children'] ?? []) as $c) {
    $ctype = $c['type'] ?? '';
    if (!empty($c['name']) && !empty($c['chip_label'])) {
        $controlLabels[$c['name']] = $c['chip_label'];
    }
    if ($ctype === 'value_match' && !empty($c['name'])) {
        $controlKeys[] = $c['name'];
    } elseif ($ctype === 'search') {
        $cmode = $c['mode'] ?? 'quickFilter';
        if ($cmode === 'event' || $cmode === 'legacy') {
            if (!empty($c['name'])) $controlKeys[] = $c['name'];
            if (!empty($c['id_field'])) $controlKeys[] = $c['id_field'];
        } else {
            $controlKeys[] = 'quickFilter';
        }
    } elseif ($ctype === 'dropdown' && !empty($c['name'])) {
        $controlKeys[] = $c['name'];
    } elseif ($ctype === 'more_filters') {
        foreach (($c['children'] ?? []) as $sub) {
            if (!empty($sub['name'])) $controlKeys[] = $sub['name'];
        }
    }
}
$paginatorKeys = ['sort', 'direction', 'page', 'limit'];

/*
 * Filters that are on but have no control in this bar — the `searchemail:`
 * behind the "My events" button. They have nowhere else to show, so the
 * panel opens itself for them; a search term does not get that treatment,
 * its own box is right there in the bar showing the term.
 */
$extraKeys = array_diff(
    array_keys(array_filter($currentFilters, function ($v) { return $v !== ''; })),
    $controlKeys,
    $paginatorKeys
);

$advId = $filterId . '-adv';

// Two counts, two jobs: the panel opens itself only when one of ITS controls
// is set, while the badge answers "is anything filtering?" — search term and
// scope included, since those stay visible with the panel folded away. The
// draft engine recomputes the badge on every change; this is the first paint.
$activeSubs = 0;
foreach (($moreFiltersChild['children'] ?? []) as $sub) {
    if (!empty($sub['name']) && isset($currentFilters[$sub['name']])
        && $currentFilters[$sub['name']] !== '') {
        $activeSubs++;
    }
}
$activeTotal = count(array_diff_key(
    array_filter($currentFilters, function ($v) { return $v !== ''; }),
    array_flip($paginatorKeys)
));
?>

<div id="<?= h($filterId) ?>" class="d-flex flex-wrap gap-2 align-items-center">

    <?php foreach ($filter_bar['children'] as $child): ?>

        <?php if ($child['type'] === 'search'): ?>
            <?php
            // Re-populate the search box from the current URL filters — 
            // read the right key so the term survives a reload (important for in-tab ajax indexes).
            $mode = $child['mode'] ?? 'quickFilter';
            if ($mode === 'legacy' || $mode === 'event') {
                $searchVal = $currentFilters[$child['name']] ?? null;
                if ($searchVal === null && !empty($child['id_field'])) {
                    $searchVal = $currentFilters[$child['id_field']] ?? null;
                }
            } else {
                $searchVal = $currentFilters['quickFilter'] ?? null;
            }
            ?>
            <div class="flex-grow-1" style="max-width: 600px">
                <div class="input-group" data-tour="index-search">
                    <input
                        class="form-control"
                        id="filterField"
                        type="text"
                        placeholder="<?= h($child['placeholder']) ?>"
                        value="<?= $searchVal !== null ? h(urldecode($searchVal)) : '' ?>"
                    >
                    <button
                        id="filterButton"
                        class="btn btn-primary"
                        type="button"
                    >
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($child['type'] === 'value_match'): ?>
            <?php
            // A second free-text filter that must NOT be confused with the index
            // search: it lives in its own labelled panel, drives its own named
            // param and is applied explicitly (button / Enter), never on blur.
            $vmId = $filterId . '-value-match';
            $vmVal = $currentFilters[$child['name']] ?? null;
            $vmVal = $vmVal !== null ? urldecode($vmVal) : '';
            $vmActive = $vmVal !== '';
            ?>
            <div class="dropdown dropdown-filters flex-shrink-0">
                <button class="btn <?= $vmActive ? 'btn-primary' : 'btn-outline-primary' ?> dropdown-toggle"
                        type="button"
                        data-bs-toggle="dropdown"
                        data-bs-auto-close="outside"
                        data-tour="index-value-match">
                    <i class="<?= h($child['icon'] ?? 'fas fa-crosshairs') ?> me-1"></i>
                    <?= h($child['label'] ?? __('Search a value')) ?>
                </button>

                <div class="dropdown-menu p-3" style="min-width: 26rem">
                    <div class="input-group">
                        <input
                            id="<?= h($vmId) ?>"
                            class="form-control topbar-filter value-match-input"
                            type="text"
                            name="<?= h($child['name']) ?>"
                            data-manual="1"
                            value="<?= h($vmVal) ?>"
                            placeholder="<?= h($child['placeholder'] ?? '') ?>"
                        >
                        <?php if ($vmActive): ?>
                            <button class="btn btn-outline-secondary value-match-clear"
                                    type="button"
                                    title="<?= __('Clear') ?>">
                                <i class="fas fa-times"></i>
                            </button>
                        <?php endif; ?>
                        <button class="btn btn-primary value-match-apply" type="button">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                    <?php if (!empty($child['hint'])): ?>
                        <div class="form-text"><?= h($child['hint']) ?></div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($child['type'] === 'dropdown'): ?>
            <select
                class="form-select flex-shrink-0 w-auto topbar-filter"
                name="<?= h($child['name']) ?>"
                aria-label="<?= h($child['label']) ?>"
            >
                <?php foreach ($child['options'] as $value => $label): ?>
                    <option value="<?= h($value) ?>"
                        <?= (isset($currentFilters[$child['name']]) && $currentFilters[$child['name']] == $value) ? 'selected' : '' ?>>
                        <?= h($label) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        <?php endif; ?>

        <?php if ($child['type'] === 'more_filters'): ?>
            <?= $this->element('genericElementsBS5/IndexTable/filter_toggle', [
                'target' => $advId,
                'label' => $child['label'],
                'count' => $activeTotal,
                'open' => ($activeSubs || $extraKeys),
            ]) ?>
        <?php endif; ?>

        <?php if ($child['type'] === 'button'): ?>
            <a href="<?= h($child['url']) ?>"
               class="<?= h($child['class']) ?> flex-shrink-0"<?php
               if (!empty($child['title'])): ?>
               title="<?= h($child['title']) ?>"<?php
               endif; ?><?php
               if (!empty($child['onclick'])): ?>
               onclick="<?= h($child['onclick']) ?>"<?php
               endif; ?>>
                <?php if (!empty($child['icon'])): ?>
                    <i class="<?= h($child['icon']) ?>"></i>
                <?php endif; ?>
                <?= h($child['label']) ?>
            </a>
        <?php endif; ?>

    <?php endforeach; ?>

    <div class="ms-auto index-filter-pager">
        <?php
        if (empty($filter_bar['skip_pagination'])) {
            echo $this->element(
                'genericElementsBS5/IndexTable/pagination_nav',
                ['maxPages' => 5, 'size' => 'sm']
            );
        }
        ?>
    </div>

    <div class="btn-group" role="group" data-tour="index-view">
        <?php if (!empty($filter_bar['view_switch'])): ?>
            <!-- Custom view switch (e.g. table / JSON) — each is a link/reload, not the default client-side table/card toggle. -->
            <?php foreach ($filter_bar['view_switch'] as $vs): ?>
                <a href="<?= h($vs['url']) ?>"
                   class="btn btn-outline-primary <?= !empty($vs['active']) ? 'active' : '' ?>"
                   title="<?= h($vs['title'] ?? '') ?>">
                    <i class="<?= h($vs['icon']) ?>"></i>
                </a>
            <?php endforeach; ?>
        <?php else: ?>
            <button
                id="viewList"
                type="button"
                class="btn btn-outline-primary active"
                title="Table View"
            >
                <i class="fas fa-list"></i>
            </button>
            <button
                id="viewCard"
                type="button"
                class="btn btn-outline-primary"
                title="Card View"
            >
                <i class="fas fa-th"></i>
            </button>
        <?php endif; ?>
    </div>

</div>

<?php if (!empty($moreFiltersChild)): ?>
    <?php
    // The advanced controls, rendered by the shared panel
    $draftFields = [];
    foreach (($moreFiltersChild['children'] ?? []) as $sub) {
        $draftFields[] = [
            'name' => $sub['name'],
            'label' => $sub['label'] ?? $sub['name'],
            'type' => 'select',
            'options' => $sub['options'] ?? [],
            'value' => isset($currentFilters[$sub['name']])
                ? urldecode($currentFilters[$sub['name']]) : '',
            'col' => $sub['col'] ?? 3,
            'help' => $sub['help'] ?? null,
        ];
    }
    ?>
    <?= $this->element('genericElementsBS5/IndexTable/filter_panel', [
        'id' => $advId,
        'open' => ($activeSubs || $extraKeys),
        'fields' => $draftFields,
        'input_class' => 'topbar-filter',
    ]) ?>
<?php endif; ?>

<?php
// Active-filters display. An index may pass an explicit `active_filters` map
// (label => value) plus a `clear_url`.
$explicitActive = $filter_bar['active_filters'] ?? null;
$isAjaxBar = $this->request->is('ajax');

$clearViaJs = false;
if ($explicitActive !== null) {
    $activeToShow = $explicitActive;
    $clearHref = $filter_bar['clear_url'] ?? ($item_url . '/' . $filterAction);
} elseif ($isAjaxBar) {
    // In an ajax tab, only this bar's own filters are removable; 
    // "Clear all" is handled in JS so it drops them while keeping the scope.
    $activeToShow = array_intersect_key($currentFilters, array_flip($controlKeys));
    $clearHref = null;
    $clearViaJs = true;
} else {
    $activeToShow = $currentFilters;
    $clearHref = $item_url . '/' . $filterAction;
}
?>
<div class="index-active-filters">
<?php // With a draft in play the chips live in its summary, buttons included. ?>
<?php if (!empty($activeToShow) && empty($moreFiltersChild)): ?>
    <div class="mt-2 d-flex align-items-center flex-wrap gap-2">

        <strong class="me-1"><?= __('Active filters') ?>:</strong>

        <?php foreach ($activeToShow as $key => $value): ?>
            <span class="badge bg-primary">
                <?= h($controlLabels[$key] ?? $key) ?>: <?= h(urldecode($value)) ?>
            </span>
        <?php endforeach; ?>

        <?php if ($clearViaJs): ?>
            <button type="button" class="filter-clear-all btn btn-sm btn-outline-danger ms-auto">
                <i class="fas fa-times"></i>
                <?= __('Clear all') ?>
            </button>
        <?php else: ?>
            <a href="<?= h($clearHref) ?>"
               class="btn btn-sm btn-outline-danger ms-auto">
                <i class="fas fa-times"></i>
                <?= __('Clear all') ?>
            </a>
        <?php endif; ?>

    </div>
<?php endif; ?>
</div>

<?php
$hasMassActions = !empty($filter_bar['delete'])
    || !empty($filter_bar['fetch'])
    || !empty($filter_bar['accept'])
    || !empty($filter_bar['discard'])
    || !empty($filter_bar['export'])
    || !empty($filter_bar['mass_edit'])
    || !empty($filter_bar['mass_tag'])
    || !empty($filter_bar['mass_local_tag'])
    || !empty($filter_bar['mass_cluster'])
    || !empty($filter_bar['mass_local_cluster'])
    || !empty($filter_bar['mass_object'])
    || !empty($filter_bar['mass_relationship'])
    || !empty($filter_bar['mass_sighting'])
    || !empty($filter_bar['enable'])
    || !empty($filter_bar['require'])
    || !empty($filter_bar['highlight'])
    || !empty($filter_bar['activate']);
?>

<?php if ($hasMassActions): ?>
<?= $this->element(
    'genericElementsBS5/IndexTable/multi_select_toolbar',
    [
        'filter_bar' => $filter_bar,
        'item_url'   => $item_url,
    ]
) ?>
<?php endif; ?>

<script>
var baseIndexUrl = "<?= h($baseurl . $item_url . '/' . $filterAction) ?>";
<?php if ($hasMassActions): ?>
var selectedItems = new Map();
<?php endif; ?>

var filterBarConfig = <?= json_encode([
    'mode'        => $searchChild['mode'] ?? 'quickFilter',
    'searchField' => $searchChild['name'] ?? 'quickFilter',
    'idField'     => $searchChild['id_field'] ?? null,
    'transport'   => $transport,
]) ?>;

(function init() {
    const filterBarEl = document.getElementById('<?= h($filterId) ?>');
    const scope = filterBarEl?.closest('.tab-pane') || document;
    // When the index is rendered inside a lazily-loaded ajax tab, keep the user in that tab
    const ajaxContainer = filterBarEl?.closest('.ajax-tab-content') || null;
    // Capture per-instance config locally
    const cfg = filterBarConfig;
    const base = baseIndexUrl;
    const itemIndexPath = '<?= h($item_url . '/' . $filterAction) ?>';

    /*
     * Only wire the table/card view toggle when it is present: indexes using a
     * custom view switch have no #viewCard and manage their own reloads, so
     * setView() must NOT run for them.
     *
     * Deferred, because setView()/isMobile() live in mispOvermind.js, which
     * this inline script does not wait for. It used to carry its own copies
     * of both — that is exactly the duplication this indirection replaces.
     */
    function setupViewToggle() {
    if (scope.querySelector('#viewCard')) {
        scope.querySelector('#viewList')?.addEventListener('click', () => setView('table', true, scope));
        scope.querySelector('#viewCard')?.addEventListener('click', () => setView('card', true, scope));

        const savedView = localStorage.getItem('indexViewMode');
        setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false, scope);

        // A narrow viewport always forces card view; otherwise defaulting to table
        function applyResponsiveView() {
            const savedView = localStorage.getItem('indexViewMode');
            setView(isMobile() ? 'card' : (savedView || 'table'), false, scope);
        }

        applyResponsiveView();

        // Re-apply whenever the viewport crosses the mobile breakpoint
        let wasMobile = isMobile();
        window.addEventListener('resize', () => {
            const nowMobile = isMobile();
            if (nowMobile !== wasMobile) {
                wasMobile = nowMobile;
                applyResponsiveView();
            }
        });
    }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupViewToggle);
    } else {
        setupViewToggle();
    }

    /* ── deferred apply, when the bar carries a `more_filters` control ──
     *
     * The advanced controls build a draft instead of firing a query each time
     * one of them changes. Only the URL work is local, because only this bar
     * knows about the `search` key prefix, the positional scope arguments
     * and the ajax tab that may wrap it.
     * See initIndexFilterDraft() in mispOvermind.js.
     *
     * Waiting for DOMContentLoaded matters: initTopbarFilterSelects() turns
     * these selects into TomSelects there, and wiring earlier would hook a
     * control about to grow a widget of its own.
     */
    let draft = null;

    function setupDraft() {
        if (typeof initScaffoldFilterDraft !== 'function') { return; }
        draft = initScaffoldFilterDraft(filterBarEl, {
            scope: scope,
            ajaxContainer: ajaxContainer,
            base: base,
            itemPath: itemIndexPath,
            mode: cfg.mode,
            transport: cfg.transport,
            searchField: cfg.searchField,
            idField: cfg.idField,
            // Keys this bar has a control for; anything else in the URL is a
            // scope it must keep and show, never a filter it owns.
            ownedKeys: <?= json_encode(array_values(array_unique(array_merge(
                $controlKeys,
                ['sort', 'direction', 'page', 'limit']
            ))), JSON_UNESCAPED_UNICODE) ?>,
            results: '#index-results',
            swap: ['#headerCountBadge', '.index-filter-pager', '.index-active-filters'],
            strings: <?= IndexFilterDraft::stringsJson() ?>,
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupDraft);
    } else {
        setupDraft();
    }

    // Build the filter URL from the ajax container's *current* fragment URL so
    // persistent scope survives a search/filter change. Scope can be a named
    // param (events: searchemail:x) or a positional pass arg (auth keys:
    // /index/<userId>) — both are preserved; only this bar's own controls and
    // pagination/sort are recomputed.
    function buildScopedUrl() {
        const src = (ajaxContainer && ajaxContainer.dataset.url) ? ajaxContainer.dataset.url : window.location.pathname;
        const parsed = parseIndexUrl(src, itemIndexPath);
        const positional = parsed.positional;
        // Keys are held unprefixed here and re-prefixed when the URL is built.
        const filters = {};
        Object.keys(parsed.named).forEach(key => {
            const plain = (cfg.mode === 'event' && key.indexOf('search') === 0) ? key.slice(6) : key;
            filters[plain] = parsed.named[key];
        });
        // A new search/filter resets pagination and sort.
        delete filters['page']; delete filters['sort']; delete filters['direction'];

        const ff = scope.querySelector('#filterField');
        const qv = ff ? ff.value.trim() : '';
        if (cfg.mode === 'legacy' || cfg.mode === 'event') {
            delete filters[cfg.searchField];
            if (cfg.idField) delete filters[cfg.idField];
            if (qv !== '') {
                const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
                const numRe = /^[0-9]+$/;
                if (cfg.idField && (uuidRe.test(qv) || numRe.test(qv))) filters[cfg.idField] = qv;
                else filters[cfg.searchField] = qv;
            }
        } else {
            delete filters['quickFilter'];
            if (qv !== '') filters['quickFilter'] = qv;
        }
        scope.querySelectorAll('.topbar-filter').forEach(el => {
            const n = el.getAttribute('name');
            if (!n) return;
            if (el.value !== '') filters[n] = el.value; else delete filters[n];
        });

        const named = {};
        Object.keys(filters).forEach(k => {
            named[(cfg.mode === 'event' ? 'search' : '') + k] = filters[k];
        });
        return formatIndexUrl(base, { positional: positional, named: named });
    }

    // Filters as a query string. Same controls as buildFilterUrl(), but the
    // values ride where a '/' survives - CakePHP reads them through
    // `$this->request->query`, which _harvestParameters() already merges.
    function buildQueryUrl() {
        const params = new URLSearchParams(window.location.search);
        // A new search resets pagination and sort.
        ['page', 'sort', 'direction'].forEach(k => params.delete(k));

        const ff = scope.querySelector('#filterField');
        const qv = ff ? ff.value.trim() : '';
        if (qv !== '') params.set(cfg.searchField, qv); else params.delete(cfg.searchField);

        scope.querySelectorAll('.topbar-filter').forEach(el => {
            const n = el.getAttribute('name');
            if (!n) return;
            if (el.value !== '') params.set(n, el.value); else params.delete(n);
        });

        const qs = params.toString();
        return base + (qs ? '?' + qs : '');
    }

    // The bar's own URL builder: query transport when asked for it, named URL
    // segments otherwise (buildFilterUrl lives in mispOvermind.js).
    function buildUrl() {
        return cfg.transport === 'query' ? buildQueryUrl() : buildFilterUrl();
    }

    function go(url) {
        if (ajaxContainer && typeof reloadAjaxTabIndex === 'function') {
            reloadAjaxTabIndex(ajaxContainer, url);
        } else {
            window.location.href = url;
        }
    }

    if (ajaxContainer) {
        // With a draft in play the search box goes through it, so a search
        // never reloads the index out from under half-filled advanced filters.
        scope.querySelector('#filterButton')?.addEventListener('click', () => draft ? draft.apply() : go(buildScopedUrl()));
        scope.querySelector('#filterField')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') { draft ? draft.apply() : go(buildScopedUrl()); } });
        scope.querySelectorAll('.topbar-filter:not([data-manual])').forEach(el => el.addEventListener('change', () => go(buildScopedUrl())));

        // "Clear all": drop this bar's own filters but keep the scope (search
        // field + dropdowns are reset, then buildScopedUrl keeps only the scope).
        scope.querySelector('.filter-clear-all')?.addEventListener('click', (e) => {
            e.preventDefault();
            const ff = scope.querySelector('#filterField');
            if (ff) ff.value = '';
            scope.querySelectorAll('.topbar-filter').forEach(el => {
                if (el.tomselect) el.tomselect.clear(true); else el.value = '';
            });
            go(buildScopedUrl());
        });

        // Pagination + sort links. Rebuild the target from the container's current
        // (scoped) URL so the scope is always kept — including the page-1 link,
        // which CakePHP renders without a /page: segment. Registered once on the
        // persistent container so reloads don't stack duplicate listeners.
        if (!ajaxContainer.dataset.indexWired) {
            ajaxContainer.dataset.indexWired = '1';
            ajaxContainer.addEventListener('click', function(e) {
                const a = e.target.closest('a[href]');
                if (!a || !ajaxContainer.contains(a)) return;
                const href = a.getAttribute('href') || '';
                const curr = ajaxContainer.dataset.url || '';

                if (a.classList.contains('page-link')) {
                    e.preventDefault();
                    const pm = href.match(/[/?&]page[:=](\d+)/);
                    const page = pm ? pm[1] : '1';
                    reloadAjaxTabIndex(ajaxContainer, curr.replace(/\/page:\d+/, '') + '/page:' + page);
                    return;
                }

                const sm = href.match(/\/sort:([^\/]+)/);
                if (sm && href.indexOf(itemIndexPath) !== -1) {
                    e.preventDefault();
                    const dm = href.match(/\/direction:([^\/]+)/);
                    let url = curr.replace(/\/page:\d+/, '').replace(/\/sort:[^\/]+/, '').replace(/\/direction:[^\/]+/, '');
                    url += '/sort:' + sm[1];
                    if (dm) url += '/direction:' + dm[1];
                    reloadAjaxTabIndex(ajaxContainer, url);
                    return;
                }
            });
        }
    } else {
        scope.querySelector('#filterButton')?.addEventListener('click', () => {
            if (draft) { draft.apply(); return; }
            window.location.href = buildUrl();
        });

        scope.querySelector('#filterField')?.addEventListener('keypress', function(e) {
            if (e.key !== 'Enter') return;
            if (draft) { draft.apply(); return; }
            window.location.href = buildUrl();
        });

        scope.querySelectorAll('.topbar-filter:not([data-manual])').forEach(el => {
            el.addEventListener('change', () => {
                window.location.href = buildUrl();
            });
        });
    }

    // `value_match` controls: free text is only applied when the user asks for
    // it (search button or Enter), so a half-typed value never triggers a
    // reload. The input still carries .topbar-filter, so the URL builders pick
    // its value up like any other filter.
    function applyFilters() {
        if (draft) { draft.apply(); return; }
        if (ajaxContainer) {
            go(buildScopedUrl());
        } else {
            window.location.href = buildUrl();
        }
    }

    // Looking a value up in the list entries can take a moment on large
    // warninglists, so the control shows it is working.
    function applyValueMatch(el) {
        const btn = el?.closest('.input-group')?.querySelector('.value-match-apply');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
        }
        applyFilters();
    }

    scope.querySelectorAll('.value-match-input').forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                applyValueMatch(input);
            }
        });
    });

    scope.querySelectorAll('.value-match-apply').forEach(btn => {
        btn.addEventListener('click', () => applyValueMatch(btn));
    });

    scope.querySelectorAll('.value-match-clear').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.closest('.input-group')?.querySelector('.value-match-input');
            if (input) {
                input.value = '';
            }
            applyFilters();
        });
    });

<?php if ($hasMassActions): ?>
    // Guard so reloading an ajax index does not stack duplicate change listeners.
    if (!window.__mispMassActionChangeWired) {
        window.__mispMassActionChangeWired = true;
        document.addEventListener('change', function(e) {
            if (!e.target.classList.contains('item-checkbox')) return;

            const checkbox  = e.target;
            const id        = checkbox.dataset.itemId;
            const canDelete = checkbox.dataset.canDelete == "1";
            const publish   = checkbox.dataset.publish;
            const enable    = checkbox.dataset.enable;
            const require   = checkbox.dataset.require;
            const highlight = checkbox.dataset.highlight;

            if (checkbox.checked) {
                selectedItems.set(id, { id, canDelete, publish, enable, require, highlight });
            } else {
                selectedItems.delete(id);
            }

            updateMultiSelectToolbar();
        });
    }
<?php endif; ?>

})();
</script>