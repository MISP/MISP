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
        <div class="col-md-auto">
            <label class="form-label fw-semibold d-block invisible">
                placeholder
            </label>
            <div class="dropdown dropdown-filters">
                <button class="btn btn-outline-primary dropdown-toggle"
                        type="button"
                        data-bs-toggle="dropdown">
                    <i class="fas fa-sliders-h me-1"></i>
                    <?= h($child['label']) ?>
                </button>

                <div class="dropdown-menu p-3" style="min-width: 250px;">
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
                    onclick="multiSelectExportEvents();">
                <i class="fas fa-file-export"></i>
                <?= __('Export') ?>
            </button>

            <button id="multi-delete-button"
                    class="btn btn-danger btn-sm d-none"
                    onclick="multiSelectDeleteEvents()">
                <i class="fas fa-trash"></i>
                <?= __('Delete') ?>
            </button>

        </div>
    </div>
</div>



<script>
var baseIndexUrl = "<?= h($index_url) ?>";

$(function() {

    /*******************************
     * View Mode Toggle (Table / Card)
     *******************************/
    function isMobile() {
        return window.innerWidth < 768;
    }

    function setView(view, save = true) {
        if (view === 'card') {
            $('#tableView').addClass('d-none');
            $('#cardView').removeClass('d-none');
            $('#viewList').removeClass('active');
            $('#viewCard').addClass('active');
        } else {
            $('#cardView').addClass('d-none');
            $('#tableView').removeClass('d-none');
            $('#viewCard').removeClass('active');
            $('#viewList').addClass('active');
        }

        if (save) {
            localStorage.setItem('indexViewMode', view);
        }
    }

    // Event listeners for view buttons
    $('#viewList').on('click', () => setView('table'));
    $('#viewCard').on('click', () => setView('card'));

    // Initialize view based on saved preference or device
    const savedView = localStorage.getItem('indexViewMode');
    setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false);


    /*******************************
     * Filter URL Builder
     *******************************/
    function buildFilterUrl() {
        const base = baseIndexUrl.replace(/\/search.*/, '');
        let filters = {};

        // Parse existing filters from URL
        const searchMatch = window.location.pathname.match(/\/search(.+)/);
        if (searchMatch) {
            const parts = searchMatch[1].split('/search');
            parts.forEach(part => {
                const [key, value] = part.split(':');
                if (key && value) filters[key] = decodeURIComponent(value);
            });
        }

        // Quick filter (search by info or ID/UUID)
        const quickValue = $('#quickFilterField').val().trim();
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

        // Apply dropdown filters
        $('.topbar-filter').each(function() {
            const name = $(this).attr('name');
            const value = $(this).val();
            if (value !== '') {
                filters[name] = value;
            } else {
                delete filters[name];
            }
        });

        // Construct final URL
        let newUrl = base;
        Object.keys(filters).forEach(key => {
            newUrl += '/search' + key + ':' + filters[key];
        });

        return newUrl;
    }

    // Event handlers for filters
    $('#quickFilterButton').on('click', () => {
        window.location.href = buildFilterUrl();
    });

    $('#quickFilterField').on('keypress', function(e) {
        if (e.which === 13) $('#quickFilterButton').click();
    });

    $('.topbar-filter').on('change', () => {
        window.location.href = buildFilterUrl();
    });


    /*******************************
     * Multi-Select Toolbar
     *******************************/
    let selectedEvents = new Map();

    // Update toolbar visibility and buttons
    function updateMultiSelectToolbar() {
        const count = selectedEvents.size;

        if (count === 0) {
            $('#multiSelectToolbar').addClass('d-none');
            return;
        }

        $('#multiSelectToolbar').removeClass('d-none');
        $('#selectedCount').text(count);

        // Show delete only if user can delete all selected events
        let canDeleteAll = true;
        selectedEvents.forEach(event => {
            if (!event.canDelete) canDeleteAll = false;
        });

        if (canDeleteAll) {
            $('#multi-delete-button').removeClass('d-none');
        } else {
            $('#multi-delete-button').addClass('d-none');
        }
    }

    // Checkbox change handler
    $(document).on('change', '.event-checkbox', function() {
        const id = $(this).data('event-id');
        const canDelete = $(this).data('can-delete') == 1;

        if ($(this).is(':checked')) {
            selectedEvents.set(id, { id: id, canDelete: canDelete });
        } else {
            selectedEvents.delete(id);
        }

        updateMultiSelectToolbar();
    });
}); // end of $(function)
</script>