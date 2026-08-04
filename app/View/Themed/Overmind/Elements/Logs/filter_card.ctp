<?php
/*
 * Shared filter card for the log indexes (application / audit / access).
 *
 * Two complementary layers:
 *  - a quick-search box that filters the CURRENTLY LOADED page client-side,
 *    matching against the FULL text of each row (timeline .tl-entry / table <tr>,
 *    marked with data-search) and hiding emptied .tl-group day headers;
 *  - a collapsible grid of advanced filters that build a CakePHP named-parameter
 *    URL (/index/key:value/...) and reload. Filtering is automatic: any change
 *    to an input applies immediately. Select inputs use TomSelect.
 *
 * Expected variables:
 *  - $item_url      : string base path, e.g. '/admin/access_logs'
 *  - $search        : ['placeholder' => <string>] for the client-side page search
 *  - $fields        : advanced filter definitions
 *  - $pager_element : optional element path rendered on the right of the bar
 *
 */

$named = $this->request->params['named'] ?? [];
$uid = 'logfilter-' . dechex(mt_rand());
$clearHref = $baseurl . $item_url . '/index';

$fields = array_values(array_filter($fields ?? [], function ($f) {
    return !isset($f['requirement']) || $f['requirement'];
}));

$currentValue = function ($name) use ($named) {
    if (!isset($named[$name])) {
        return '';
    }
    $v = $named[$name];
    return is_array($v) ? implode('||', $v) : (string)$v;
};

// Active (server-side) filters → chips + collapsed/expanded state.
$activeFilters = [];
foreach ($fields as $f) {
    $val = $currentValue($f['name']);
    if ($val !== '') {
        $label = $f['label'] ?? $f['name'];
        if (($f['type'] ?? '') === 'select' && isset($f['options'][$val])) {
            $display = $f['options'][$val];
        } else {
            $display = urldecode($val);
        }
        $activeFilters[] = ['label' => $label, 'value' => $display];
    }
}
$activeCount = count($activeFilters);
?>

<div class="card shadow-sm mb-4" id="<?= h($uid) ?>">
    <div class="card-body">

        <div class="d-flex flex-wrap gap-2 align-items-center">

            <!-- Client-side page search (matches the full text of each row) -->
            <div class="flex-grow-1" style="max-width: 600px;">
                <div class="input-group">
                    <input type="text"
                           class="form-control log-client-filter"
                           placeholder="<?= h($search['placeholder'] ?? __('Filter this page…')) ?>"
                           autocomplete="off">
                    <button type="button" class="btn btn-primary log-client-btn">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>
            <span class="text-muted small log-client-count"></span>

            <?php if (!empty($fields)): ?>
                <button type="button"
                        class="btn btn-outline-primary dropdown-toggle flex-shrink-0"
                        data-bs-toggle="collapse"
                        data-bs-target="#<?= h($uid) ?>-adv"
                        aria-expanded="<?= $activeCount ? 'true' : 'false' ?>">
                    <i class="fas fa-sliders-h me-1"></i><?= __('More Filters') ?>
                    <?php if ($activeCount): ?>
                        <span class="badge bg-primary ms-1"><?= (int)$activeCount ?></span>
                    <?php endif; ?>
                </button>
            <?php endif; ?>

            <?php if (!empty($pager_element)): ?>
                <div class="ms-auto">
                    <?= $this->element($pager_element, ['maxPages' => 5, 'size' => 'sm']) ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if (!empty($fields)): ?>
            <div class="collapse <?= $activeCount ? 'show' : '' ?>" id="<?= h($uid) ?>-adv">
                <hr>
                <div class="row g-3">
                    <?php foreach ($fields as $f):
                        $name = $f['name'];
                        $type = $f['type'] ?? 'text';
                        $col  = (int)($f['col'] ?? 4);
                        $val  = $currentValue($name);
                    ?>
                        <div class="col-md-<?= $col ?>">
                            <label class="form-label small fw-semibold mb-1"><?= h($f['label']) ?></label>

                            <?php if ($type === 'select'): ?>
                                <select class="form-select form-select-sm tom-select" data-log-filter="<?= h($name) ?>"
                                        data-placeholder="<?= h($f['options'][''] ?? __('Any')) ?>">
                                    <?php foreach (($f['options'] ?? []) as $optVal => $optLabel): ?>
                                        <option value="<?= h($optVal) ?>" <?= ((string)$optVal === $val) ? 'selected' : '' ?>>
                                            <?= h($optLabel) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>

                            <?php elseif ($type === 'date'): ?>
                                <input type="date" class="form-control form-control-sm"
                                       data-log-filter="<?= h($name) ?>" value="<?= h($val) ?>">

                            <?php elseif ($type === 'number'): ?>
                                <input type="number" class="form-control form-control-sm"
                                       data-log-filter="<?= h($name) ?>"
                                       <?= isset($f['step']) ? 'step="' . h($f['step']) . '"' : '' ?>
                                       placeholder="<?= h($f['placeholder'] ?? '') ?>" value="<?= h($val) ?>">

                            <?php else: ?>
                                <input type="text" class="form-control form-control-sm"
                                       data-log-filter="<?= h($name) ?>"
                                       placeholder="<?= h($f['placeholder'] ?? '') ?>"
                                       value="<?= h(urldecode($val)) ?>" autocomplete="off">
                            <?php endif; ?>

                            <?php if (!empty($f['help'])): ?>
                                <div class="form-text small"><?= h($f['help']) ?></div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!empty($activeFilters)): ?>
            <div class="mt-2 d-flex align-items-center flex-wrap gap-2">
                <strong class="me-1"><?= __('Active filters') ?>:</strong>
                <?php foreach ($activeFilters as $af): ?>
                    <span class="badge bg-primary"><?= h($af['label']) ?>: <?= h($af['value']) ?></span>
                <?php endforeach; ?>
                <a href="<?= h($clearHref) ?>" class="btn btn-sm btn-outline-danger ms-auto">
                    <i class="fas fa-times me-1"></i><?= __('Clear all') ?>
                </a>
            </div>
        <?php endif; ?>

    </div>
</div>

<script>
(function () {
    var root = document.getElementById(<?= json_encode($uid) ?>);
    if (!root) { return; }
    var base = <?= json_encode($clearHref) ?>;

    /* ── advanced (server-side) filters — auto-apply on any change ──── */
    function apply() {
        var parts = [];
        root.querySelectorAll('[data-log-filter]').forEach(function (el) {
            var name = el.getAttribute('data-log-filter');
            var val  = (el.value || '').trim();
            if (name && val !== '') {
                parts.push(name + ':' + encodeURIComponent(val));
            }
        });
        window.location.href = base + (parts.length ? '/' + parts.join('/') : '');
    }

    root.querySelectorAll('[data-log-filter]').forEach(function (el) {
        el.addEventListener('change', apply);
        el.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); apply(); }
        });
    });

    if (typeof initTomSelect === 'function') { initTomSelect(root); }

    /* ── client-side page filter — matches the full text of each row ── */
    var searchEl = root.querySelector('.log-client-filter');
    var btnEl    = root.querySelector('.log-client-btn');
    var countEl  = root.querySelector('.log-client-count');
    function clientFilter() {
        var q = (searchEl.value || '').toLowerCase().trim();
        var rows = document.querySelectorAll('[data-search]');
        var visible = 0;
        rows.forEach(function (el) {
            var hay = (el.textContent || '').toLowerCase();
            var match = !q || hay.indexOf(q) !== -1;
            el.classList.toggle('d-none', !match);
            if (match) { visible++; }
        });
        document.querySelectorAll('.tl-group').forEach(function (g) {
            g.classList.toggle('d-none', !g.querySelector('[data-search]:not(.d-none)'));
        });
        if (countEl) {
            countEl.textContent = q ? (visible + ' / ' + rows.length) : '';
        }
    }
    if (searchEl) { searchEl.addEventListener('input', clientFilter); }
    if (btnEl)    { btnEl.addEventListener('click', clientFilter); }
}());
</script>
