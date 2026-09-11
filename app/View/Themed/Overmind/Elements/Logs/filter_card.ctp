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

App::uses('IndexFilterDraft', 'Tools');

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
// Raw values: formatIndexUrl() in mispOvermind.js does the encoding.
$preserved = [];
foreach (['sort', 'direction', 'limit'] as $key) {
    if (isset($named[$key]) && $named[$key] !== '') {
        $preserved[$key] = (string)$named[$key];
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
    'applied' => $applied,
    'appliedQuick' => $quickValue,
    'fields' => $fieldMeta,
    'results' => '#log-index-results',
    'strings' => IndexFilterDraft::strings(),
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
                <?= $this->element('genericElementsBS5/IndexTable/filter_toggle', [
                    'target' => $uid . '-adv',
                    'count' => $activeCount + ($quickValue !== '' ? 1 : 0),
                    'open' => (bool)$activeCount,
                ]) ?>
            <?php endif; ?>

            <?php if (!empty($pager_element)): ?>
                <div class="ms-auto log-filter-pager">
                    <?= $this->element($pager_element, ['maxPages' => 5, 'size' => 'sm']) ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if (!empty($fields)): ?>
            <?php
            // The grid and the summary come from the shared panel, so this
            // bar and the scaffold's `more_filters` cannot drift apart.
            $draftFields = [];
            foreach ($fields as $f) {
                $draftFields[] = $f + ['value' => $currentValue($f['name']), 'col' => 4];
            }
            ?>
            <?= $this->element('genericElementsBS5/IndexTable/filter_panel', [
                'id' => $uid . '-adv',
                'open' => (bool)$activeCount,
                'fields' => $draftFields,
                'input_class' => 'tom-select',
            ]) ?>
        <?php else: ?>
            <div class="filter-draft-summary border-top mt-3 pt-3"></div>
        <?php endif; ?>

    </div>

    <script type="application/json" class="log-filter-config"><?= json_encode($config, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
</div>
