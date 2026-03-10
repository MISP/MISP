<?php
$filter_bar = $scaffold_data['filter_bar'] ?? null;
if (empty($filter_bar)) {
    return;
}

$currentPath = $this->request->here(false);
$currentFilters = [];

if (preg_match('/\/search(.+)/', $currentPath, $matches)) {
    $parts = explode('/search', $matches[1]);

    foreach ($parts as $part) {
        if (strpos($part, ':') !== false) {
            list($key, $value) = explode(':', $part);
            $currentFilters[$key] = $value;
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
                <input
                    id="quickFilterField"
                    type="text"
                    name="eventinfo"
                    class="form-control"
                    placeholder="<?= $child['placeholder'] ?>"
                    value="<?= isset($currentFilters['eventinfo']) ? h($currentFilters['eventinfo']) : '' ?>"
                >
                <button
                    id="quickFilterButton"
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

                <a href="<?= h($index_url) ?>"
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
                <?= __('Selected events') ?>:
                <span id="selectedCount">0</span>
            </strong>

            <button id="multi-export-button"
                    class="btn btn-primary btn-sm ms-3"
                    onclick="multiSelectEvents('<?php echo $baseurl; ?>/events/restSearchExport');">
                <i class="fas fa-file-export"></i>
                <?= __('Export') ?>
            </button>

            <button id="multi-delete-button"
                    class="btn btn-danger btn-sm d-none"
                    onclick="multiSelectEvents('<?php echo $baseurl; ?>/events/delete');">
                <i class="fas fa-trash"></i>
                <?= __('Delete') ?>
            </button>

        </div>
    </div>
</div>



<script>
var baseIndexUrl = "<?= h($index_url) ?>";
let selectedEvents = new Map();

document.addEventListener("DOMContentLoaded", function () {

    /*******************************
     * View Mode Toggle (Table / Card)
     *******************************/
    function isMobile() {
        return window.innerWidth < 768;
    }

    function setView(view, save = true) {
        const tableView = document.getElementById('tableView');
        const cardView = document.getElementById('cardView');
        const viewList = document.getElementById('viewList');
        const viewCard = document.getElementById('viewCard');

        if (view === 'card') {
            tableView.classList.add('d-none');
            cardView.classList.remove('d-none');
            viewList.classList.remove('active');
            viewCard.classList.add('active');
        } else {
            cardView.classList.add('d-none');
            tableView.classList.remove('d-none');
            viewCard.classList.remove('active');
            viewList.classList.add('active');
        }

        if (save) {
            localStorage.setItem('indexViewMode', view);
        }
    }

    document.getElementById('viewList')?.addEventListener('click', () => setView('table'));
    document.getElementById('viewCard')?.addEventListener('click', () => setView('card'));

    const savedView = localStorage.getItem('indexViewMode');
    setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false);


    /*******************************
     * Filter URL Builder
     *******************************/
    function buildFilterUrl() {
        const base = baseIndexUrl.replace(/\/search.*/, '');
        let filters = {};

        const searchMatch = window.location.pathname.match(/\/search(.+)/);
        if (searchMatch) {
            const parts = searchMatch[1].split('/search');
            parts.forEach(part => {
                const [key, value] = part.split(':');
                if (key && value) filters[key] = decodeURIComponent(value);
            });
        }

        const quickField = document.getElementById('quickFilterField');
        const quickValue = quickField ? quickField.value.trim() : '';

        delete filters['eventinfo'];
        delete filters['eventid'];

        if (quickValue !== '') {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            const numberRegex = /^[0-9]+$/;

            if (uuidRegex.test(quickValue) || numberRegex.test(quickValue)) {
                filters['eventid'] = encodeURIComponent(quickValue);
            } else {
                filters['eventinfo'] = encodeURIComponent(quickValue);
            }
        }

        document.querySelectorAll('.topbar-filter').forEach(el => {
            const name = el.getAttribute('name');
            const value = el.value;

            if (!name) return;

            if (value !== '') {
                filters[name] = value;
            } else {
                delete filters[name];
            }

        });

        let newUrl = base;
        Object.keys(filters).forEach(key => {
            newUrl += '/search' + key + ':' + filters[key];
        });

        return newUrl;
    }

    document.getElementById('quickFilterButton')?.addEventListener('click', () => {
        window.location.href = buildFilterUrl();
    });

    document.getElementById('quickFilterField')?.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            window.location.href = buildFilterUrl();
        }
    });

    document.querySelectorAll('.topbar-filter').forEach(el => {
        el.addEventListener('change', () => {
            window.location.href = buildFilterUrl();
        });
    });


    /*******************************
     * Multi-Select Toolbar
     *******************************/
    function updateMultiSelectToolbar() {
        const toolbar = document.getElementById('multiSelectToolbar');
        const selectedCount = document.getElementById('selectedCount');
        const deleteButton = document.getElementById('multi-delete-button');

        const count = selectedEvents.size;

        if (count === 0) {
            toolbar?.classList.add('d-none');
            return;
        }

        toolbar?.classList.remove('d-none');

        if (selectedCount) {
            selectedCount.textContent = count;
        }

        let canDeleteAll = true;
        selectedEvents.forEach(event => {
            if (!event.canDelete) {
                canDeleteAll = false;
            }
        });

        if (canDeleteAll) {
            deleteButton?.classList.remove('d-none');
        } else {
            deleteButton?.classList.add('d-none');
        }
    }

    /*******************************
     * Checkbox change handler
     *******************************/
    document.addEventListener('change', function(e) {

        if (!e.target.classList.contains('event-checkbox')) return;

        const checkbox = e.target;

        const id = checkbox.dataset.eventId;
        const canDelete = checkbox.dataset.canDelete == "1";

        if (checkbox.checked) {
            selectedEvents.set(id, { id: id, canDelete: canDelete });
        } else {
            selectedEvents.delete(id);
        }

        updateMultiSelectToolbar();
    });

});
</script>