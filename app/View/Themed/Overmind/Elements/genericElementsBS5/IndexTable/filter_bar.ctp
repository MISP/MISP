<?php
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

$hasActiveFilters = !empty($currentFilters);

$filterId = 'filter-bar-' . uniqid();

$searchChild = null;
foreach ($filter_bar['children'] as $child) {
    if ($child['type'] === 'search') {
        $searchChild = $child;
        break;
    }
}
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
                <div class="input-group">
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
            <div class="dropdown dropdown-filters flex-shrink-0">
                <button class="btn btn-outline-primary dropdown-toggle"
                        type="button"
                        data-bs-toggle="dropdown"
                        data-bs-auto-close="false">
                    <i class="fas fa-sliders-h me-1"></i>
                    <?= h($child['label']) ?>
                </button>

                <div class="dropdown-menu p-3">
                    <?php foreach ($child['children'] as $sub): ?>
                        <div class="mb-3">
                            <label class="form-label fw-semibold">
                                <?= h($sub['label']) ?>
                            </label>
                            <select class="form-select topbar-filter"
                                    name="<?= h($sub['name']) ?>">
                                <?php foreach (($sub['options'] ?? []) as $value => $label): ?>
                                    <option value="<?= h($value) ?>"
                                        <?= (isset($currentFilters[$sub['name']]) && urldecode($currentFilters[$sub['name']]) == $value) ? 'selected' : '' ?>>
                                        <?= h($label) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($child['type'] === 'button'): ?>
            <a href="<?= h($child['url']) ?>"
               class="<?= h($child['class']) ?> flex-shrink-0">
                <?php if (!empty($child['icon'])): ?>
                    <i class="<?= h($child['icon']) ?>"></i>
                <?php endif; ?>
                <?= h($child['label']) ?>
            </a>
        <?php endif; ?>

    <?php endforeach; ?>

    <div class="ms-auto">
        <?php
        if (empty($filter_bar['skip_pagination'])) {
            echo $this->element(
                'genericElementsBS5/IndexTable/pagination_nav',
                ['maxPages' => 5, 'size' => 'sm']
            );
        }
        ?>
    </div>

    <div class="btn-group" role="group">
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

<?php
// Active-filters display. An index may pass an explicit `active_filters` map
// (label => value) plus a `clear_url`.
$explicitActive = $filter_bar['active_filters'] ?? null;
$isAjaxBar = $this->request->is('ajax');

// Which URL params are *this bar's own controls* (removable) — everything else
// (e.g. searchemail: scope, positional pass-args) must never show as a
// removable chip and must survive "Clear all".
$controlKeys = [];
foreach (($filter_bar['children'] ?? []) as $c) {
    $ctype = $c['type'] ?? '';
    if ($ctype === 'search') {
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
<?php if (!empty($activeToShow)): ?>
    <div class="mt-2 d-flex align-items-center flex-wrap gap-2">

        <strong class="me-1"><?= __('Active filters') ?>:</strong>

        <?php foreach ($activeToShow as $key => $value): ?>
            <span class="badge bg-primary">
                <?= h($key) ?>: <?= h(urldecode($value)) ?>
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
]) ?>;

function setView(view, save = true, scope = document) {
    const tableView = scope.querySelector('#tableView');
    const cardView  = scope.querySelector('#cardView');
    const viewList  = scope.querySelector('#viewList');
    const viewCard  = scope.querySelector('#viewCard');

    if (view === 'card') {
        tableView?.classList.add('d-none');
        cardView?.classList.remove('d-none');
        viewList?.classList.remove('active');
        viewCard?.classList.add('active');
    } else {
        cardView?.classList.add('d-none');
        tableView?.classList.remove('d-none');
        viewCard?.classList.remove('active');
        viewList?.classList.add('active');
    }

    if (save) localStorage.setItem('indexViewMode', view);
}

function isMobile() {
    return window.innerWidth < 1000;
}

(function init() {
    const filterBarEl = document.getElementById('<?= h($filterId) ?>');
    const scope = filterBarEl?.closest('.tab-pane') || document;
    // When the index is rendered inside a lazily-loaded ajax tab, keep the user in that tab
    const ajaxContainer = filterBarEl?.closest('.ajax-tab-content') || null;
    // Capture per-instance config locally
    const cfg = filterBarConfig;
    const base = baseIndexUrl;
    const itemIndexPath = '<?= h($item_url . '/' . $filterAction) ?>';

    // Only wire the table/card view toggle when it is present.
    // Indexes using a custom view switch have no #viewCard and manage their
    // own reloads, so we must NOT run setView() in that case.
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

    // Build the filter URL from the ajax container's *current* fragment URL so
    // persistent scope survives a search/filter change. Scope can be a named
    // param (events: searchemail:x) or a positional pass arg (auth keys:
    // /index/<userId>) — both are preserved; only this bar's own controls and
    // pagination/sort are recomputed.
    function buildScopedUrl() {
        const src = (ajaxContainer && ajaxContainer.dataset.url) ? ajaxContainer.dataset.url : window.location.pathname;
        const positional = [];
        const filters = {};
        const after = src.indexOf(itemIndexPath) !== -1 ? src.split(itemIndexPath)[1] : '';
        (after || '').split('/').filter(Boolean).forEach(seg => {
            const idx = seg.indexOf(':');
            if (idx < 0) { positional.push(seg); return; }          // scope (e.g. userId)
            let key = seg.slice(0, idx);
            if (cfg.mode === 'event' && key.indexOf('search') === 0) key = key.slice(6);
            filters[key] = decodeURIComponent(seg.slice(idx + 1));
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

        let url = base;
        positional.forEach(p => { url += '/' + p; });
        Object.keys(filters).forEach(k => {
            const v = encodeURIComponent(filters[k]);
            url += (cfg.mode === 'event') ? ('/search' + k + ':' + v) : ('/' + k + ':' + v);
        });
        return url;
    }

    function go(url) {
        if (ajaxContainer && typeof reloadAjaxTabIndex === 'function') {
            reloadAjaxTabIndex(ajaxContainer, url);
        } else {
            window.location.href = url;
        }
    }

    if (ajaxContainer) {
        scope.querySelector('#filterButton')?.addEventListener('click', () => go(buildScopedUrl()));
        scope.querySelector('#filterField')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') go(buildScopedUrl()); });
        scope.querySelectorAll('.topbar-filter').forEach(el => el.addEventListener('change', () => go(buildScopedUrl())));

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
            window.location.href = buildFilterUrl();
        });

        scope.querySelector('#filterField')?.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') window.location.href = buildFilterUrl();
        });

        scope.querySelectorAll('.topbar-filter').forEach(el => {
            el.addEventListener('change', () => {
                window.location.href = buildFilterUrl();
            });
        });
    }

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