<?php
$top_bar = $scaffold_data['top_bar'] ?? null;
if (empty($top_bar)) {
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
<?php foreach ($top_bar['children'] as $child): ?>

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
        <div class="col-md-2">
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


<script>
var baseIndexUrl = "<?= h($index_url) ?>";
$(function() {

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

    $('#viewList').on('click', function() {
        setView('table');
    });

    $('#viewCard').on('click', function() {
        setView('card');
    });

    const savedView = localStorage.getItem('indexViewMode');
    if (savedView) {
        setView(savedView, false);
    } else {
        setView(isMobile() ? 'card' : 'table', false);
    }

    // Function to build the new URL with filters
    function buildFilterUrl() {
        const base = baseIndexUrl.replace(/\/search.*/, '');
        let filters = {};

        // Fetch existing filters from the URL if present
        const searchMatch = window.location.pathname.match(/\/search(.+)/);
        if (searchMatch) {
            const parts = searchMatch[1].split('/search');
            parts.forEach(part => {
                const [key, value] = part.split(':');
                if (key && value) {
                    filters[key] = decodeURIComponent(value);
                }
            });
        }

        // Update / add the quick filter for eventinfo
        const quickValue = $('#quickFilterField').val();
        if (quickValue.trim() !== '') {
            filters['eventinfo'] = encodeURIComponent(quickValue.trim());
        } else {
            delete filters['eventinfo'];
        }

        // Update filters based on dropdowns
        $('.topbar-filter').each(function() {
            const name = $(this).attr('name');
            const value = $(this).val();
            if (value !== '') {
                filters[name] = value;
            } else {
                delete filters[name];
            }
        });

        // Construct the new URL
        let newUrl = base;
        Object.keys(filters).forEach(key => {
            newUrl += '/search' + key + ':' + filters[key];
        });

        return newUrl;
    }

    // Event handler for the quick filter button
    $('#quickFilterButton').on('click', function() {
        const newUrl = buildFilterUrl();
        window.location.href = newUrl;
    });

    // Event handler for pressing Enter in the quick filter input
    $('#quickFilterField').on('keypress', function(e) {
        if (e.which === 13) {
            $('#quickFilterButton').click();
        }
    });

    // Event handler for dropdown changes
    $('.topbar-filter').on('change', function() {
        const newUrl = buildFilterUrl();
        window.location.href = newUrl;
    });

});
</script>