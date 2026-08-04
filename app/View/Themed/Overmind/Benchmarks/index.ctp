<?php
/**
 * Benchmarks index (not yet tested)
 */
if (empty($ajax)) {
    $this->set('headerTitle', __('Benchmark results'));
    $this->set('headerDescription', __('Collected benchmarks. Filter further by scope, field, average and aggregation.'));
}

// Build the quick-filter link groups (same URL logic as the core view).
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
                                <a href="<?= h($qf['url']) ?>"
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
            'skip_pagination' => true,
            'fields' => $fields,
        ],
    ],
    'item_url' => '/benchmarks',
]);
?>
