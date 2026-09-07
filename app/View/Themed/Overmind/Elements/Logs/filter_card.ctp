<?php
/*
 * Shared filter card for the log indexes (application / audit / access).
 *
 * Nothing here queries on its own: the inputs build up a *draft*, the draft is
 * shown back as chips, and one "Apply filters" button runs it. Log tables hold
 * millions of rows and a multi-column LIKE cannot use an index, so a filter
 * that fired on every blur meant paying for a full scan per keystroke-and-tab.
 * Applying reloads the results through ajax (see initLogFilterCard() in
 * mispOvermind.js) rather than the whole page, and swaps `#log-index-results`
 * — every view using this element must wrap its results in that container.
 *
 * Two kinds of filter, both server-side — what you see is what the query ran
 * on, not a narrowing of the rows that happened to be on screen:
 *  - a free-text box searching the WHOLE index. Its term travels in the query
 *    string (`?quickFilter=…`) rather than as a named parameter, because a
 *    named URL segment cannot carry a '/' and searching the access log means
 *    searching URLs. The controller turns it into an OR over the columns that
 *    make sense for that index (IndexFilterComponent::quickFilterConditions).
 *  - a collapsible grid of advanced filters, carried as CakePHP named
 *    parameters (/index/key:value/...).
 *
 * Sort, direction and limit are named parameters owned by the paginator, not by
 * this bar: they are carried across so that filtering does not silently reset
 * the column a table is sorted on. PaginatorHelper already carries the query
 * string back the other way, so paging and sorting keep the search term.
 *
 * Expected variables:
 *  - $item_url      : string base path, e.g. '/admin/access_logs'
 *  - $search        : ['placeholder' => <string>] for the free-text box
 *  - $fields        : advanced filter definitions
 *  - $pager_element : optional element path rendered on the right of the bar
 *
 */

$named = $this->request->params['named'] ?? [];
$uid = 'logfilter-' . dechex(mt_rand());
$clearHref = $baseurl . $item_url . '/index';

// Set by the controller, which also honours a legacy named parameter.
$quickValue = $quickFilter ?? (string)($this->request->query('quickFilter') ?? '');

$fields = array_values(array_filter($fields ?? [], function ($f) {
    return !isset($f['requirement']) || $f['requirement'];
}));

/*
 * The bar writes its filters to the query string and reads them back from
 * there first: a named URL segment cannot carry a '/', so `url:%2Fevents` on
 * the access log arrives with the value silently dropped. Named parameters are
 * still read, so older links and hand-written URLs keep working.
 */
$query = $this->request->query ?? [];
$currentValue = function ($name) use ($named, $query) {
    $v = $query[$name] ?? $named[$name] ?? null;
    if ($v === null || $v === '') {
        return '';
    }
    return is_array($v) ? implode('||', $v) : (string)$v;
};

/*
 * A dropdown lists what a column is *supposed* to hold — an action that has
 * since been renamed, or a model dropped from the searchable list, is not in
 * it. Without its own option the <select> falls back to "Any", so the bar
 * would report no filter while the results below are very much filtered, and
 * the next apply would quietly drop it. Give the value a home instead.
 */
foreach ($fields as $i => $f) {
    if (($f['type'] ?? '') !== 'select') {
        continue;
    }
    $val = $currentValue($f['name']);
    if ($val !== '' && !array_key_exists($val, $f['options'] ?? [])) {
        $fields[$i]['options'][$val] = $val;
    }
}

// Named parameters this bar does not own but must not drop when it reloads.
$preserved = [];
foreach (['sort', 'direction', 'limit'] as $key) {
    if (isset($named[$key]) && $named[$key] !== '') {
        $preserved[] = $key . ':' . rawurlencode((string)$named[$key]);
    }
}

/*
 * What the page is currently showing, and enough about each field for the
 * chips to be rendered client-side as the draft changes. `options` lets a
 * select chip read "Action: Remove tag" rather than "Action: remove_tag".
 */
$applied = [];
$fieldMeta = [];
foreach ($fields as $f) {
    $name = $f['name'];
    $val = $currentValue($name);
    $fieldMeta[$name] = [
        'label' => $f['label'] ?? $name,
        'options' => (($f['type'] ?? '') === 'select') ? ($f['options'] ?? []) : null,
    ];
    if ($val !== '') {
        $applied[$name] = $val;
    }
}
$activeCount = count($applied);

$config = [
    'base' => $clearHref,
    'preserved' => $preserved,
    'quickName' => 'quickFilter',
    'quickLabel' => __('Search'),
    'applied' => $applied,
    'appliedQuick' => $quickValue,
    'fields' => $fieldMeta,
    'results' => '#log-index-results',
    'strings' => [
        'apply' => __('Apply filters'),
        'applied' => __('Filters applied'),
        'pendingOne' => __('1 change not applied yet'),
        'pendingMany' => __('%s changes not applied yet'),
        'noFilter' => __('No filter — showing every entry.'),
        'clearAll' => __('Clear all'),
        'remove' => __('Remove this filter'),
        'willBeRemoved' => __('Will be removed'),
        'notApplied' => __('Not applied yet'),
        'loadError' => __('Could not load the filtered results. Please try again.'),
    ],
];
?>

<div class="card shadow-sm mb-4" id="<?= h($uid) ?>" data-log-filter-card>
    <div class="card-body">

        <div class="d-flex flex-wrap gap-2 align-items-center">

            <!-- Free-text search over the whole index -->
            <div class="flex-grow-1" style="max-width: 600px;">
                <div class="input-group">
                    <input type="text"
                           class="form-control log-quick-filter"
                           placeholder="<?= h($search['placeholder'] ?? __('Search all entries…')) ?>"
                           title="<?= __('Searches every entry, not just this page. Two characters minimum.') ?>"
                           value="<?= h($quickValue) ?>"
                           autocomplete="off">
                    <button type="button" class="btn btn-primary log-quick-btn"
                            title="<?= __('Apply the filters') ?>">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>

            <?php if (!empty($fields)): ?>
                <button type="button"
                        class="btn btn-outline-primary dropdown-toggle flex-shrink-0"
                        data-bs-toggle="collapse"
                        data-bs-target="#<?= h($uid) ?>-adv"
                        aria-expanded="<?= $activeCount ? 'true' : 'false' ?>">
                    <i class="fas fa-sliders-h me-1"></i><?= __('More Filters') ?>
                    <span class="badge bg-primary ms-1 log-filter-count <?= $activeCount ? '' : 'd-none' ?>"><?= (int)$activeCount ?></span>
                </button>
            <?php endif; ?>

            <?php if (!empty($pager_element)): ?>
                <div class="ms-auto log-filter-pager">
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
                                       value="<?= h($val) ?>" autocomplete="off">
                            <?php endif; ?>

                            <?php if (!empty($f['help'])): ?>
                                <div class="form-text small"><?= h($f['help']) ?></div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Draft summary + apply, rendered by initLogFilterCard().
                     It sits inside the collapse so that folding the advanced
                     filters away folds their chips and buttons with them; the
                     "More Filters" badge is what stays behind to say that
                     filters are on. -->
                <div class="log-filter-summary border-top mt-3 pt-3"></div>
            </div>
        <?php else: ?>
            <div class="log-filter-summary border-top mt-3 pt-3"></div>
        <?php endif; ?>

    </div>

    <script type="application/json" class="log-filter-config"><?= json_encode($config, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
</div>
