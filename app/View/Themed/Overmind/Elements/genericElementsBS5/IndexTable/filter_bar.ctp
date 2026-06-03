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

$searchChild = null;
foreach ($filter_bar['children'] as $child) {
    if ($child['type'] === 'search') {
        $searchChild = $child;
        break;
    }
}
?>

<div class="d-flex flex-wrap gap-2 align-items-center">

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
                        data-bs-toggle="dropdown">
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
                                <?php foreach ($sub['options'] as $value => $label): ?>
                                    <option value="<?= h($value) ?>"
                                        <?= (isset($currentFilters[$sub['name']]) && $currentFilters[$sub['name']] == $value) ? 'selected' : '' ?>>
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
                    <i class="fas fa-<?= h($child['icon']) ?>"></i>
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

<?php if ($hasActiveFilters): ?>
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

<?= $this->element(
    'genericElementsBS5/IndexTable/multi_select_toolbar',
    [
        'filter_bar' => $filter_bar,
        'item_url'   => $item_url,
    ]
) ?>

<script>
var baseIndexUrl = "<?= h($baseurl . $item_url . '/index') ?>";
var selectedItems = new Map();

var filterBarConfig = <?= json_encode([
    'mode'        => $searchChild['mode'] ?? 'quickFilter',
    'searchField' => $searchChild['name'] ?? 'quickFilter',
    'idField'     => $searchChild['id_field'] ?? null,
]) ?>;

function setView(view, save = true) {
    const tableView = document.getElementById('tableView');
    const cardView  = document.getElementById('cardView');
    const viewList  = document.getElementById('viewList');
    const viewCard  = document.getElementById('viewCard');

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

    document.getElementById('viewList')?.addEventListener('click', () => setView('table'));
    document.getElementById('viewCard')?.addEventListener('click', () => setView('card'));

    const savedView = localStorage.getItem('indexViewMode');
    setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false);

    document.getElementById('filterButton')?.addEventListener('click', () => {
        window.location.href = buildFilterUrl();
    });

    document.getElementById('filterField')?.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') window.location.href = buildFilterUrl();
    });

    document.querySelectorAll('.topbar-filter').forEach(el => {
        el.addEventListener('change', () => {
            window.location.href = buildFilterUrl();
        });
    });

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

})();
</script>