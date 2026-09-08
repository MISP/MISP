<?php
/**
 *
 * Read-only general card for a remote event preview.
 *
 */

$evt   = $data['Event'] ?? [];
$org   = $data['Org'] ?? [];
$orgc  = $data['Orgc'] ?? [];
$sg    = $data['SharingGroup'] ?? [];

$distribution = (int)($evt['distribution'] ?? 0);
$isPublished  = !empty($evt['published']);


$analysisMap = [
    0 => ['label' => __('Initial'),   'dot' => '#0d6efd'],
    1 => ['label' => __('Ongoing'),   'dot' => '#fd7e14'],
    2 => ['label' => __('Completed'), 'dot' => '#198754'],
];
$threatMap = [
    0 => ['label' => __('Low'),       'color' => '#ffc107'],
    1 => ['label' => __('Medium'),    'color' => '#fd7e14'],
    2 => ['label' => __('High'),      'color' => '#dc3545'],
    3 => ['label' => __('Undefined'), 'color' => '#41464b'],
];
$analysisLevel = (int)($evt['analysis'] ?? 0);
// Backend: 1=High, 2=Medium, 3=Low, 4=Undefined -> display index 0=Low..3=Undef
$threatLevelId = (int)($evt['threat_level_id'] ?? 4);
$threatLevel   = [1 => 2, 2 => 1, 3 => 0, 4 => 3][$threatLevelId] ?? 3;
$analysis = $analysisMap[$analysisLevel] ?? $analysisMap[0];
$threat   = $threatMap[$threatLevel] ?? $threatMap[3];

// Dates -> header description strip (like the classic event view).
$descParts = [];
if (!empty($evt['date'])) {
    $descParts[] = '<span><i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . h($evt['date']) . '</span>';
}
if (!empty($evt['timestamp'])) {
    $descParts[] = '<span><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($evt['timestamp']) . '</span>';
}
$this->set('headerDescription',
    '<span class="d-inline-flex gap-3 flex-wrap">' . implode('', $descParts) . '</span>');

// ── Stats computed from the preloaded remote data ──────────────────────────
$attrByCategory = [];
$objByName = [];
$attrTotal = 0;
$objTotal  = 0;
foreach ($data['objects'] ?? [] as $previewObject) {
    $objectType = $previewObject['objectType'] ?? '';
    if ($objectType === 'attribute') {
        $attrTotal++;
        $cat = $previewObject['category'] ?: __('Other');
        $attrByCategory[$cat] = ($attrByCategory[$cat] ?? 0) + 1;
    } elseif ($objectType === 'object') {
        $objTotal++;
        $name = $previewObject['name'] ?? __('Other');
        $objByName[$name] = ($objByName[$name] ?? 0) + 1;
    }
}
arsort($attrByCategory);
arsort($objByName);

$tagCount = count(array_filter(
    $data['Tag'] ?? [],
    function ($t) { return empty($t['is_galaxy']); }
));
$clusterCount = 0;
foreach ($data['Galaxy'] ?? [] as $gal) {
    $clusterCount += count($gal['GalaxyCluster'] ?? []);
}

$statsUid = 'preview-stats-' . h($evt['id'] ?? '0');
$stats = [
    'attributes' => ['total' => $attrTotal, 'by_category' => $attrByCategory],
    'objects'    => ['total' => $objTotal,  'by_name'    => $objByName],
];
?>

<div class="card mb-3 shadow-sm" id="preview-general-card">
    <div class="card-body">

        <!-- Identifiers + Organisations -->
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <i class="fas fa-fingerprint me-1"></i>
                        <?= __('Identifiers') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
                        <div class="d-flex align-items-center gap-2">
                            <span class="text-muted small fw-bold">ID</span>
                            <span class="bg-light border rounded px-2 py-1 fw-semibold small font-monospace">
                                #<?= h($evt['id'] ?? '') ?>
                            </span>
                        </div>
                        <div class="d-flex align-items-center gap-2">
                            <span class="text-muted small fw-bold flex-shrink-0">UUID</span>
                            <div class="d-inline-flex align-items-center gap-1 bg-light border rounded px-2 py-1">
                                <span class="font-monospace small text-truncate"><?= h($evt['uuid'] ?? '') ?></span>
                                <button
                                    class="text-muted border-0 bg-transparent p-0 ms-1 flex-shrink-0"
                                    onclick="copyValueToClipboard('<?= h($evt['uuid'] ?? '') ?>', '<?= __('UUID copied to clipboard') ?>')"
                                    data-bs-toggle="tooltip"
                                    title="<?= __('Copy UUID') ?>"
                                    aria-label="<?= __('Copy UUID') ?>">
                                    <i class="fas fa-copy" style="font-size:0.75rem;"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Created by -->
            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <span class="misp-icon misp-icon-user1 misp-hexagone"></span>
                        <?= __('Created by') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 px-2 py-1">
                        <div class="d-flex align-items-center gap-2">
                            <?= $this->OrgImg->getOrgLogoV2($orgc, 20, false) ?>
                            <span class="fw-medium"><?= h($orgc['name'] ?? '') ?></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Distribution + Publication -->
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <i class="fas fa-broadcast-tower me-1"></i>
                        <?= __('Distribution') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between">
                        <?= $this->element('genericElementsBS5/Badges/distribution', [
                            'distribution' => $distribution,
                            'full'         => true
                        ]); ?>
                        <?php if ($distribution === 4 && !empty($sg['name'])): ?>
                            <span class="d-inline-flex align-items-center gap-1 small">
                                <span class="misp-icon misp-icon-sharing-group misp-hexagone text-primary"></span>
                                <?= h($sg['name']) ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <i class="fas fa-paper-plane me-1"></i>
                        <?= __('Publication') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
                        <?= $this->element('genericElementsBS5/Badges/boolean', [
                            'boolean'    => $isPublished,
                            'full'       => true,
                            'true'       => __('Published'),
                            'false'      => __('Unpublished'),
                            'trueColor'  => 'success',
                            'falseColor' => 'warning',
                            'trueIcon'   => 'fa-upload',
                            'falseIcon'  => 'fa-warning',
                        ]); ?>
                        <?php if ($isPublished && !empty($evt['publish_timestamp'])): ?>
                            <div class="d-flex align-items-center gap-1 text-muted small">
                                <i class="fas fa-history fa-fw"></i>
                                <?= $this->Time->time($evt['publish_timestamp']) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Threat level + Analysis (same visualisation as classic view) -->
        <div class="row g-2 align-items-start mb-3">
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-2"><?= __('Analysis') ?></div>
                <?php $analysisPct = (int)(($analysisLevel + 1) / 3 * 100); ?>
                <div class="d-flex align-items-center gap-2">
                    <div class="flex-fill" style="height:4px;border-radius:2px;background:#e9ecef;overflow:hidden;">
                        <div style="height:100%;width:<?= $analysisPct ?>%;border-radius:2px;background:<?= h($analysis['dot']) ?>;"></div>
                    </div>
                    <span class="small fw-semibold flex-shrink-0" style="color:<?= h($analysis['dot']) ?>;"><?= h($analysis['label']) ?></span>
                </div>
            </div>
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-2"><?= __('Threat Level') ?></div>
                <?php $threatPct = $threatLevel < 3 ? (int)(($threatLevel + 1) / 3 * 100) : 5; ?>
                <div class="d-flex align-items-center gap-2">
                    <div class="flex-fill" style="height:4px;border-radius:2px;background:#e9ecef;overflow:hidden;">
                        <div style="height:100%;width:<?= $threatPct ?>%;border-radius:2px;background:<?= h($threat['color']) ?>;"></div>
                    </div>
                    <span class="small fw-semibold flex-shrink-0" style="color:<?= h($threat['color']) ?>;"><?= h($threat['label']) ?></span>
                </div>
            </div>
        </div>

        <hr class="my-4">

        <!-- Attribute / object statistics (computed locally, drawn with Chart.js) -->
        <div id="<?= $statsUid ?>">
            <div class="row g-4 mb-4" id="<?= $statsUid ?>-charts"></div>

            <div class="row g-3">
                <div class="col-6 col-md-6">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'misp-icon misp-icon-tag misp-simple',
                        'color' => '#DB6A47',
                        'label' => __('Tags'),
                        'value' => $tagCount,
                        'onclick' => "var c=document.getElementById('preview-tags-card');if(c){c.scrollIntoView({behavior:'smooth'});}",
                    ]); ?>
                </div>
                <div class="col-6 col-md-6">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'misp-icon misp-icon-galaxy misp-simple',
                        'color' => '#8B5CF6',
                        'label' => __('Clusters'),
                        'value' => $clusterCount,
                        'onclick' => "var c=document.getElementById('preview-galaxy-card');if(c){c.scrollIntoView({behavior:'smooth'});}",
                    ]); ?>
                </div>
            </div>
        </div>

    </div>
</div>

<script>
(function () {
    var uid   = <?= json_encode($statsUid) ?>;
    var stats = <?= json_encode($stats) ?>;

    var PALETTE = [
        '#3B82F6','#10B981','#F59E0B','#EF4444','#8B5CF6',
        '#EC4899','#14B8A6','#F97316','#6366F1','#84CC16',
        '#06B6D4','#E11D48'
    ];

    var chartDefs = [
        {
            key:   'objects',
            tab:   '#tab-attributes',
            title: <?= json_encode(__('Objects')) ?>,
            total: stats.objects.total,
            data:  stats.objects.by_name,
            icon:  'misp-icon misp-icon-object misp-hexagone',
            color: '#524948',
            empty: <?= json_encode(__('No objects')) ?>
        },
        {
            key:   'attributes',
            tab:   '#tab-attributes',
            title: <?= json_encode(__('Attributes')) ?>,
            total: stats.attributes.total,
            data:  stats.attributes.by_category,
            icon:  'misp-icon misp-icon-attribute misp-hexagone',
            color: '#97CC04',
            empty: <?= json_encode(__('No attributes')) ?>
        }
    ];

    function render() {
        var row = document.getElementById(uid + '-charts');
        if (!row) { return; }
        row.innerHTML = '';

        chartDefs.forEach(function (def) {
            var col = document.createElement('div');
            col.className = 'col-md-6';

            if (!def.total) {
                col.innerHTML =
                    '<div class="d-flex align-items-center justify-content-center'
                    + ' h-100 text-muted py-4 gap-2">'
                    + '<i class="' + def.icon + ' opacity-50"></i>'
                    + '<span class="small">' + def.empty + '</span>'
                    + '</div>';
                row.appendChild(col);
                return;
            }

            var labels = Object.keys(def.data);
            var values = Object.values(def.data);
            var colors = labels.map(function (_, i) { return PALETTE[i % PALETTE.length]; });
            var canvasId = uid + '-chart-' + def.key;

            col.innerHTML =
                '<div class="d-flex flex-column h-100">'
                + '<div class="d-flex align-items-center text-muted small text-uppercase fw-bold mb-3">'
                + '<i class="' + def.icon + ' fs-3 me-1" style="color:' + def.color + '"></i>'
                + def.title
                + '</div>'
                + '<div class="d-flex align-items-center gap-4 flex-wrap">'
                + '<div class="position-relative flex-shrink-0" style="width:140px;height:140px;">'
                + '<canvas id="' + canvasId + '"></canvas>'
                + '<div class="position-absolute top-50 start-50 translate-middle text-center lh-1">'
                + '<div class="fw-bold fs-4">' + def.total + '</div>'
                + '<div class="text-muted" style="font-size:.65rem;text-transform:uppercase;">'
                + <?= json_encode(__('total')) ?>
                + '</div></div></div>'
                + '<div class="flex-fill" style="min-width:0;">'
                + '<ul class="list-unstyled mb-0 small">'
                + labels.map(function (lbl, i) {
                    var pct = def.total > 0 ? Math.round(values[i] / def.total * 100) : 0;
                    return '<li class="d-flex align-items-center gap-2 mb-1">'
                        + '<span class="rounded-circle flex-shrink-0" style="width:10px;height:10px;background:'
                        + colors[i] + ';display:inline-block;"></span>'
                        + '<span class="text-truncate flex-fill" title="' + lbl + '">' + lbl + '</span>'
                        + '<span class="text-muted ms-1 flex-shrink-0">'
                        + values[i] + ' <span class="opacity-50">(' + pct + '%)</span></span>'
                        + '</li>';
                }).join('')
                + '</ul></div></div></div>';

            row.appendChild(col);

            (function tryChart() {
                if (typeof Chart === 'undefined') { setTimeout(tryChart, 100); return; }
                var ctx = document.getElementById(canvasId);
                if (!ctx) { return; }
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{ data: values, backgroundColor: colors, borderWidth: 2, hoverOffset: 4 }]
                    },
                    options: {
                        cutout: '68%',
                        responsive: true,
                        plugins: {
                            legend: { display: false },
                            tooltip: { callbacks: { label: function (c) {
                                var pct = def.total > 0 ? Math.round(c.raw / def.total * 100) : 0;
                                return ' ' + c.raw + ' (' + pct + '%)';
                            } } }
                        }
                    }
                });
            }());
        });
    }

    if (document.readyState !== 'loading') { render(); }
    else { document.addEventListener('DOMContentLoaded', render); }
}());
</script>
