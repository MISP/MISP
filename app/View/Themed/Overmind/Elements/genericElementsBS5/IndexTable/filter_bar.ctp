<?php
$filter_bar = $scaffold_data['filter_bar'] ?? null;
if (empty($filter_bar)) {
    return;
}

$currentPath = $this->request->here(false);
$currentFilters = [];

if (preg_match('~/index/(.+)~', $currentPath, $matches)) {
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
            $searchKey = ($child['mode'] ?? 'quickFilter') === 'legacy'
                ? ($child['name'] ?? 'quickFilter')
                : 'quickFilter';
            ?>
            <div class="flex-grow-1" style="max-width: 600px">
                <div class="input-group">
                    <input
                        class="form-control"
                        id="filterField"
                        type="text"
                        placeholder="<?= h($child['placeholder']) ?>"
                        value="<?= isset($currentFilters[$searchKey]) ? h(urldecode($currentFilters[$searchKey])) : '' ?>"
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
        <?= $this->element(
            'genericElementsBS5/IndexTable/pagination_nav',
            ['maxPages' => 5, 'size' => 'sm']
        ) ?>
    </div>

    <div class="btn-group" role="group">
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
    </div>

</div>

<?php if ($hasActiveFilters && !$this->request->is('ajax')): ?>
    <div class="mt-2 d-flex align-items-center flex-wrap gap-2">

        <strong class="me-1"><?= __('Active filters') ?>:</strong>

        <?php foreach ($currentFilters as $key => $value): ?>
            <span class="badge bg-primary">
                <?= h($key) ?>: <?= h(urldecode($value)) ?>
            </span>
        <?php endforeach; ?>

        <a href="<?= h($item_url . '/index') ?>"
           class="btn btn-sm btn-outline-danger ms-auto">
            <i class="fas fa-times"></i>
            <?= __('Clear all') ?>
        </a>

    </div>
<?php endif; ?>

<?php
$hasMassActions = !empty($filter_bar['delete'])
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
var baseIndexUrl = "<?= h($baseurl . $item_url . '/index') ?>";
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

(function init() {
    const scope = document.getElementById('<?= h($filterId) ?>')?.closest('.tab-pane') || document;

    scope.querySelector('#viewList')?.addEventListener('click', () => setView('table', true, scope));
    scope.querySelector('#viewCard')?.addEventListener('click', () => setView('card', true, scope));

    const savedView = localStorage.getItem('indexViewMode');
    setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false, scope);

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

<?php if ($hasMassActions): ?>
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
<?php endif; ?>

})();
</script>