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
?>

<div class="row g-3 align-items-end">
<?php foreach ($filter_bar['children'] as $child): ?>

    <?php if ($child['type'] === 'search'): ?>
        <div class="col-md-4">
            <label class="form-label fw-semibold">
                <?= $child['button'] ?>
            </label>

            <div class="input-group">
                <?php
                $searchKey = ($searchChild['mode'] ?? 'quickFilter') === 'legacy'
                    ? ($searchChild['name'] ?? 'quickFilter')
                    : 'quickFilter';
                ?>
                <input
                    class="form-control"
                    id="filterField"
                    type="text"
                    placeholder="<?= $child['placeholder'] ?>"
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
        <div class="col-md-1">
            <label class="form-label fw-semibold">
                <?= h($child['label']) ?>
            </label>

            <select
                class="form-select topbar-filter"
                name="<?= h($child['name']) ?>"
            >
                <?php foreach ($child['options'] as $value => $label): ?>
                    <option value="<?= h($value) ?>"
                        <?= (isset($currentFilters[$child['name']]) && $currentFilters[$child['name']] == $value) ? 'selected' : '' ?>>
                        <?= h($label) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
    <?php endif; ?>

    <?php if ($child['type'] === 'more_filters'): ?>
        <div class="col-md-2">
            <label class="form-label fw-semibold d-block invisible">
                placeholder
            </label>
            <div class="dropdown dropdown-filters w-100">
                <button class="btn btn-outline-primary dropdown-toggle"
                        type="button"
                        data-bs-toggle="dropdown">
                    <i class="fas fa-sliders-h me-1"></i>
                    <?= h($child['label']) ?>
                </button>

                <div class="dropdown-menu p-3 w-100">
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
        </div>
    <?php endif; ?>

    <?php if ($child['type'] === 'button'): ?>
        <div class="col-md-auto">
            <a href="<?= h($child['url']) ?>" class="<?= h($child['class']) ?>">
                <?php if (!empty($child['icon'])): ?>
                    <i class="fas fa-<?= h($child['icon']) ?>"></i>
                <?php endif; ?>
                <?= h($child['label']) ?>
            </a>
        </div>
    <?php endif; ?>

<?php endforeach; ?>

    <div class="col-md-auto ms-auto">
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
</div>

<?php if ($hasActiveFilters): ?>
    <div class="row mt-3">
        <div class="col-12">
            <div class="p-2 bg-light border rounded d-flex align-items-center flex-wrap gap-2">

                <strong class="me-2">
                    <?= __('Active filters') ?>:
                </strong>

                <?php foreach ($currentFilters as $key => $value): ?>
                    <span class="badge bg-primary">
                        <?= h($key) ?>: <?= h(urldecode($value)) ?>
                    </span>
                <?php endforeach; ?>

                <a href="<?= h($item_url . '/index')?>"
                   class="btn btn-sm btn-outline-danger ms-auto">
                    <i class="fas fa-times"></i>
                    <?= __('Clear all') ?>
                </a>

            </div>
        </div>
    </div>
<?php endif; ?>

<div id="multiSelectToolbar"
     class="row mt-3 d-none">

    <div class="col-12">
        <div class="p-2 border rounded bg-light d-flex align-items-center gap-2">

            <strong>
                <?= __('Selected items') ?>:
                <span id="selectedCount">0</span>
            </strong>

            <?php if (!empty($filter_bar['export'])): ?>
                <button id="multi-export-button"
                        class="btn btn-primary btn-sm ms-3"
                        title="<?=__('Export selected attributes')?>"
                        aria-label="<?=__('Export selected attributes')?>"
                        onclick="multiSelectItems('<?php echo h($baseurl . $item_url . '/restSearchExport');?>')">
                    <i class="fas fa-file-export"></i>
                    <?= __('Export') ?>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_edit'])): ?>
                <button id="mass-edit-button"
                        class="btn btn-secondary btn-sm d-none"
                        title="<?=__('Edit selected attributes')?>"
                        aria-label="<?=__('Edit selected attributes')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-edit text-white"></i>
                    <span class="text-white"> <?= __('Edit') ?></span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_tag'])): ?>
                <button id="mass-tag-button"
                        class="btn btn-tag-light btn-sm d-none"
                        title="<?=__('Add Tag on selected attributes')?>"
                        aria-label="<?=__('Add Tag on selected attributes')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-tag text-tag-dark"></i>
                    <span class="text-tag-dark"> <?= __('Tag') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_local_tag'])): ?>
                <button id="mass-local-tag-button"
                        class="btn btn-tag-light btn-sm d-none"
                        style="border: 2px dashed #6B2B06"
                        title="<?=__('Add Local Tag on selected attributes')?>"
                        aria-label="<?=__('Add Local Tag on selected attributes')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-user text-tag-dark"></i>
                    <span class="text-tag-dark"> <?= __('Local Tag') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_cluster'])): ?>
                <button id="mass-cluster-button"
                        class="btn btn-galaxy-light btn-sm d-none"
                        title="<?=__('Add Cluster on selected attributes')?>"
                        aria-label="<?=__('Add Cluster to selected attributes')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fab fa-galactic-republic text-galaxy-dark"></i>
                    <span class="text-galaxy-dark"> <?= __('Cluster') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_local_cluster'])): ?>
                <button id="mass-local-cluster-button"
                        class="btn btn-galaxy-light btn-sm d-none"
                        style="border: 2px dashed #084298"
                        title="<?=__('Add Local Cluster on selected attributes')?>"
                        aria-label="<?=__('Add Local Cluster to selected attributes')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-user text-galaxy-dark"></i>
                    <span class="text-galaxy-dark"> <?= __('Local Cluster') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_object'])): ?>
                <button id="mass-object-button"
                        class="btn btn-object-dark btn-sm d-none"
                        title="<?=__('Group selected Attributes into an Object')?>"
                        aria-label="<?=__('Group selected Attributes into an Object')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-cube text-white"></i>
                    <span class="text-white"> <?= __('Object') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_relationship'])): ?>
                <button id="mass-relationship-button"
                        class="btn btn-relationship-light btn-sm d-none"
                        title="<?=__('Create new relationship for selected entities')?>"
                        aria-label="<?=__('Create new relationship for selected entities')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-diagram-project text-relationship-dark"></i>
                    <span class="text-relationship-dark"> <?= __('Relationship') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['mass_sighting'])): ?>
                <button id="mass-sighting-button"
                        class="btn btn-sighting-dark btn-sm d-none"
                        title="<?=__('Sightings display for selected attributes')?>"
                        aria-label="<?=__('Sightings display for selected attributes')?>"
                        onclick="multiSelectItems('#')">
                    <i class="fas fa-eye text-white"></i>
                    <span class="text-white"> <?= __('Sightings') ?> </span>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['enable'])): ?>
                <button id="mass-enable-button"
                        class="btn btn-success btn-sm d-none"
                        title="<?=__('Enable selected items')?>"
                        onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massEnable');?>')">
                    <i class="fas fa-play"></i> <?= __('Enable') ?>
                </button>
                <button id="mass-disable-button"
                        class="btn btn-warning btn-sm d-none"
                        title="<?=__('Disable selected items')?>"
                        onclick="multiSelectItems('<?= h($baseurl . $item_url . '/massDisable');?>')">
                    <i class="fas fa-stop"></i> <?= __('Disable') ?>
                </button>
            <?php endif; ?>

            <?php if (!empty($filter_bar['delete'])): ?>
                <button id="multi-delete-button"
                        class="btn btn-danger btn-sm d-none"
                        title="<?=__('Delete selected items')?>"
                        aria-label="<?=__('Delete selected items')?>"
                        onclick="multiSelectItems('<?php echo h($baseurl . $item_url . $filter_bar['delete']);?>')">
                    <i class="fas fa-trash"></i>
                    <?= __('Delete') ?>
                </button>
            <?php endif; ?>
        </div>
    </div>
</div>



<script>
var baseIndexUrl = "<?php echo h($baseurl . $item_url . '/index'); ?>";
var selectedItems = new Map();

<?php
$searchChild = null;
foreach ($filter_bar['children'] as $child) {
    if ($child['type'] === 'search') {
        $searchChild = $child;
        break;
    }
}
?>
var filterBarConfig = <?= json_encode([
    'mode'         => $searchChild['mode'] ?? 'quickFilter',
    'searchField'  => $searchChild['name'] ?? 'quickFilter',
    'idField'      => $searchChild['id_field'] ?? null,
])
?>;

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

// In the case of an ajax injected index
(function init() {

    /*******************************
     * View Mode Toggle (Table / Card)
     *******************************/

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


    /*******************************
     * Checkbox change handler
     *******************************/
    document.addEventListener('change', function(e) {
        if (!e.target.classList.contains('item-checkbox')) return;

        const checkbox = e.target;
        const id       = checkbox.dataset.itemId;
        const canDelete = checkbox.dataset.canDelete == "1";

        if (checkbox.checked) {
            selectedItems.set(id, { id, canDelete });
        } else {
            selectedItems.delete(id);
        }

        updateMultiSelectToolbar();
    });

})();
</script>