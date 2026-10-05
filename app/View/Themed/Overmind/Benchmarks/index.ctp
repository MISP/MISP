<?php
/**
 * Benchmark results
 *
 * Two shapes from one action. Pin a scope AND a key (scope:user/key:5, which
 * is what the User view's tab asks for) and the question is "what does this
 * one cost?" — Elements/Benchmarks/focus_panel answers it. Leave either open
 * and the question is "who is the most expensive?", which is the ranked index
 * below.
 */
if (empty($ajax)) {
    $this->set('headerTitle', __('Benchmark results'));
    $this->set('headerDescription', __('Collected benchmarks. Filter further by scope, field, average and aggregation.'));
}

$isFocused = !empty($filters['key'])
    && !empty($filters['scope'])
    && $filters['scope'] !== 'all';

// Says why the screen is empty, or why its figures stopped moving.
echo $this->element('Benchmarks/collection_notice', [
    'benchmarkingEnabled' => $benchmarkingEnabled,
    'recordedDays' => $recordedDays,
]);

if ($isFocused) {
    echo $this->element('Benchmarks/focus_panel', [
        'data' => $data,
        'filters' => $filters,
    ]);
} else {

// Build the quick-filter link groups
$quickFilters = [];
foreach ($settings as $key => $settingData) {
    $url = $baseurl . '/benchmarks/index';
    foreach ($filters as $s => $v) {
        if ($v && $s != $key) {
            if (is_array($v)) {
                foreach ($v as $multiV) {
                    $url .= '/' . $s . '[]:' . $multiV;
                }
            } else {
                $url .= '/' . $s . ':' . $v;
            }
        }
    }
    if ($key != 'average' && $key != 'aggregate') {
        $quickFilters[$key][] = [
            'url' => $url,
            'text' => __('All'),
            'active' => empty($filters[$key]),
        ];
    }
    foreach ($settingData as $settingElement) {
        $text = $settingElement;
        if ($key == 'average') {
            $text = $settingElement ? __('average / request') : __('total');
        }
        if ($key == 'aggregate') {
            $text = $settingElement ? __('aggregate') : __('daily');
        }
        $quickFilters[$key][] = [
            'url' => $url . '/' . $key . ':' . $settingElement,
            'text' => $text,
            'active' => $filters[$key] == $settingElement,
        ];
    }
}

$filterGroups = [
    'scope' => __('Scope'),
    'field' => __('Field'),
    'average' => __('Mode'),
    'aggregate' => __('Aggregation'),
];

$fields = [
    ['name' => __('Date'), 'sort' => 'date', 'data_path' => 'date', 'element' => 'generic_field'],
    ['name' => __('Scope'), 'sort' => 'scope', 'data_path' => 'scope', 'element' => 'generic_field'],
    ['name' => __('Key'), 'sort' => 'text', 'data_path' => 'text', 'element' => 'generic_field'],
    ['name' => __('Field'), 'sort' => 'field', 'data_path' => 'field', 'element' => 'generic_field'],
    [
        'name' => __('Value'),
        'sort' => 'value',
        'element' => 'custom',
        'function' => function ($row) {
            return empty($row['unit'])
                ? h($row['value'])
                : h($row['value'] . ' ' . $row['unit']);
        },
    ],
];
?>

<div class="container-fluid">
    <!-- QUICK FILTERS -->
    <div class="card shadow-sm mb-4">
        <div class="card-body d-flex flex-wrap gap-4">
            <?php foreach ($filterGroups as $groupKey => $groupLabel): ?>
                <?php if (!empty($quickFilters[$groupKey])): ?>
                    <div>
                        <div class="text-muted small text-uppercase fw-bold mb-1"><?= h($groupLabel) ?></div>
                        <div class="btn-group btn-group-sm" role="group" aria-label="<?= h($groupLabel) ?>">
                            <?php foreach ($quickFilters[$groupKey] as $qf): ?>
                                <a href="<?= h($qf['url']) ?>" data-bench-filter
                                   class="btn <?= !empty($qf['active']) ? 'btn-primary' : 'btn-outline-secondary' ?>">
                                    <?= h($qf['text']) ?>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'fields' => $fields,
        ],
    ],
    'item_url' => '/benchmarks',
]);

}
?>

<script>
/* A quick filter is a link, and a link inside a lazy tab would navigate the
 * whole page to a layout-less fragment — bindAjaxTabIndexNav() only claims
 * pagination and `sort:` links, so these would escape it. Swap the tab's
 * content instead, the way IndexTable/filter_bar does. Outside a tab the
 * link is left to navigate normally. */
(function () {
    if (window.__benchFilterBound) return;
    window.__benchFilterBound = true;

    document.addEventListener('click', function (event) {
        var link = event.target.closest ? event.target.closest('a[data-bench-filter]') : null;
        if (!link) return;
        var tab = link.closest('.ajax-tab-content');
        if (!tab || typeof window.reloadAjaxTabIndex !== 'function') return;
        event.preventDefault();
        window.reloadAjaxTabIndex(tab, link.getAttribute('href'));
    });
})();
</script>
