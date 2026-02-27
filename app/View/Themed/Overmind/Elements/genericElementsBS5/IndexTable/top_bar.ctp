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
                    class="form-control"
                    placeholder="<?= $child['placeholder'] ?>"
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
                    <option value="<?= h($value) ?>">
                        <?= h($label) ?>
                    </option>
                <?php endforeach; ?>
            </select>
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



<script>
$(function() {
    function isMobile() {
        return window.innerWidth < 768; // Bootstrap md breakpoint
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
        // Si aucun choix sauvegardé
        if (isMobile()) {
            setView('card', false);
        } else {
            setView('table', false);
        }
    }

});
</script>