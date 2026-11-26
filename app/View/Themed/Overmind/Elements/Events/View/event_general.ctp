<?php
$event    = $data['Event']      ?? [];
$org      = $data['Org']        ?? [];
$orgc     = $data['Orgc']       ?? [];
$sg       = $data['SharingGroup'] ?? [];
$eventTags= $data['EventTag']  ?? [];
$user     = $data['User']       ?? [];

$analysisStops = [
    ['value' => 0, 'title' => __('Initial'),   'tone' => '#0d6efd', 'sub' => __('Raw intelligence')],
    ['value' => 1, 'title' => __('Ongoing'),   'tone' => '#fd7e14', 'sub' => __('Under investigation')],
    ['value' => 2, 'title' => __('Completed'), 'tone' => '#198754', 'sub' => __('Verified & closed')],
];

/* Lowest risk first — the ids themselves run the other way (1 is High). */
$threatStops = [
    ['value' => 4, 'title' => __('Undefined'), 'tone' => '#41464b', 'sub' => __('No risk')],
    ['value' => 3, 'title' => __('Low'),       'tone' => '#ffc107', 'sub' => __('Opportunistic')],
    ['value' => 2, 'title' => __('Medium'),    'tone' => '#fd7e14', 'sub' => __('Targeted campaign')],
    ['value' => 1, 'title' => __('High'),      'tone' => '#dc3545', 'sub' => __('Active exploitation')],
];

$analysisLevel  = (int)($event['analysis']        ?? 0);
$threatLevelId  = (int)($event['threat_level_id'] ?? 4);
$distribution   = (int)($event['distribution']    ?? 0);
$isPublished    = !empty($event['published']);
$disableCorrel  = !empty($event['disable_correlation']);

$descParts = [];
if (!empty($event['date'])) {
    $descParts[] = '<span>'
        . '<i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . h($event['date'])
        . '</span>';
}
if (!empty($event['timestamp'])) {
    $descParts[] = '<span>'
        . '<i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($event['timestamp'])
        . '</span>';
}
$headerDescription = '<span class="d-inline-flex gap-3 flex-wrap">'
    . implode('', $descParts)
    . '</span>';
$this->set('headerDescription', $headerDescription);
?>

<div class="card mb-3 shadow-sm" data-tour="event-general">
    <div class="card-body">

        <!-- ── ANALYSIS + THREAT LEVEL ────────────────────────── -->
        <div class="row g-4 mb-3">
            <div class="col-12 col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-2">
                    <?= __('Analysis') ?>
                </div>
                <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                    'field'    => 'analysis',
                    'value'    => $analysisLevel,
                    'options'  => $analysisStops,
                    'readonly' => true,
                ]) ?>
            </div>
            <div class="col-12 col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-2">
                    <?= __('Threat Level') ?>
                </div>
                <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                    'field'    => 'threat_level_id',
                    'value'    => $threatLevelId,
                    'options'  => $threatStops,
                    'readonly' => true,
                ]) ?>
            </div>
        </div>

        <!-- ── PUBLICATION ───────────────────────────────────── -->
        <div class="mb-3">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Publication') ?>
            </div>
            <div class="d-flex align-items-center flex-wrap column-gap-3 row-gap-1">
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
                <?php if (!empty($event['first_publication'])): ?>
                    <span class="d-inline-flex align-items-center gap-1 text-muted small">
                        <i class="fas fa-flag fa-fw"></i>
                        <span class="fw-medium"><?= __('First:') ?></span>
                        <?= $this->Time->time($event['first_publication']) ?>
                    </span>
                <?php endif; ?>
                <?php if (!empty($event['publish_timestamp'])): ?>
                    <span class="d-inline-flex align-items-center gap-1 text-muted small">
                        <i class="fas fa-history fa-fw"></i>
                        <span class="fw-medium"><?= __('Last:') ?></span>
                        <?= $this->Time->time($event['publish_timestamp']) ?>
                    </span>
                <?php endif; ?>
            </div>
        </div>

        <!-- ── CORRELATION + STATUS + EXTENSIONS ─────────────── -->
        <div class="row g-2 align-items-start mb-3">

            <div class="col-12 col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Correlation') ?>
                </div>
                <?= $this->element('genericElementsBS5/Badges/boolean', [
                    'boolean'    => !$disableCorrel,
                    'full'       => true,
                    'true'       => __('Enabled'),
                    'false'      => __('Disabled'),
                    'trueColor'  => 'success',
                    'falseColor' => 'danger',
                    'trueIcon'   => 'fa-link',
                    'falseIcon'  => 'fa-unlink',
                ]); ?>
            </div>

            <div class="col-12 col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Status') ?>
                </div>
                <div class="d-flex align-items-center gap-2 flex-wrap">
                    <?php if (!empty($event['locked'])): ?>
                        <span class="badge text-bg-secondary d-inline-flex align-items-center px-2 py-1">
                            <i class="fas fa-lock me-1"></i>
                            <?= __('Locked') ?>
                        </span>
                    <?php endif; ?>
                    <?php if (!empty($event['protected']) && $event['protected'] === true): ?>
                        <span class="badge d-inline-flex align-items-center px-2 py-1"
                              style="background:#fff3cd;color:#856404;border:1px solid #856404;font-weight:500;"
                              data-bs-toggle="tooltip"
                              title="<?= __('Protected events can only be updated by signatories') ?>">
                            <i class="fas fa-shield-alt me-1"></i>
                            <?= __('Protected') ?>
                        </span>
                    <?php else: ?>
                        <span class="badge d-inline-flex align-items-center px-2 py-1"
                              style="background:#e2e3e5;color:#41464b;border:1px solid #41464b;font-weight:500;"
                              data-bs-toggle="tooltip"
                              title="<?= __('Unprotected events can be updated by any user with write access to the event') ?>">
                            <i class="fas fa-shield-alt me-1"></i>
                            <?= __('Unprotected') ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- EXTENSIONS: what this event extends, what extends it -->
            <?= $this->element('Events/View/event_extensions', [
                'data' => $data,
            ]) ?>

        </div>

        <hr class="my-4">

        <!--  STATISTICS  -->
        <?php
        $eventId = h($event['id'] ?? '');
        $statsUid = 'evtstats-' . $eventId;

        $clusterCount = 0;
        $galaxyTagNames = [];
        foreach ($data['Galaxy'] ?? [] as $gal) {
            $clusterCount += count($gal['GalaxyCluster'] ?? []);
            foreach ($gal['GalaxyCluster'] ?? [] as $cluster) {
                if (!empty($cluster['tag_name'])) {
                    $galaxyTagNames[strtolower($cluster['tag_name'])] = true;
                }
            }
        }
        $tagCount = count(array_filter(
            $eventTags,
            fn($et) => empty($et['Tag']['is_galaxy'])
                || !isset(
                    $galaxyTagNames[strtolower($et['Tag']['name'] ?? '')]
                )
        ));
        ?>

        <div id="<?= $statsUid ?>">

            <!-- Donut charts row  -->
            <div class="row g-4 mb-4" id="<?= $statsUid ?>-charts">
                <div class="col-12 text-center py-3 text-muted">
                    <div class="spinner-border spinner-border-sm"></div>
                </div>
            </div>

            <!-- Metric pills row -->
            <div class="row g-3" id="<?= $statsUid ?>-pills">

                <!-- Tags -->
                <div class="col-6 col-md-3">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'misp-icon misp-icon-tag misp-simple',
                        'color' => '#DB6A47',
                        'label' => __('Tags'),
                        'value' => $tagCount,
                        'id'    => $statsUid . '-tags',
                        'onclick' => "window.scrollTo({top: document.getElementById('tags-card').offsetTop - window.innerHeight * 0.1, behavior:'smooth'});",
                    ]); ?>
                </div>

                <!-- Galaxy clusters -->
                <div class="col-6 col-md-3">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'misp-icon misp-icon-galaxy misp-simple',
                        'color' => '#8B5CF6',
                        'label' => __('Clusters'),
                        'value' => $clusterCount,
                        'id'    => $statsUid . '-clusters',
                        'onclick' => "window.scrollTo({top: document.getElementById('galaxy-card').offsetTop - window.innerHeight * 0.1, behavior:'smooth'});",
                    ]); ?>
                </div>

                <!-- Attachments -->
                <div class="col-6 col-md-3">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'fas fa-paperclip',
                        'color' => '#F59E0B',
                        'label' => __('Attachments'),
                        'value' => null,
                        'id'    => $statsUid . '-attachments',
                        'onclick' => "window.scrollTo({top: document.getElementById('attachment-card').offsetTop - window.innerHeight * 0.1, behavior:'smooth'});",
                    ]); ?>
                </div>

                <!-- Analyst data -->
                <div class="col-6 col-md-3">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'fas fa-comment-dots',
                        'color' => '#8F2D56',
                        'label' => __('Analyst datas'),
                        'value' => null,
                        'id'    => $statsUid . '-analyst-datas',
                        'onclick' => "window.scrollTo({top: document.getElementById('analyst-data-card').offsetTop - window.innerHeight * 0.1, behavior:'smooth'});",
                    ]); ?>
                </div>

            </div>

        </div>

    </div>
</div>

<script>
(function () {
    var uid      = <?= json_encode($statsUid) ?>;
    var eventId  = <?= json_encode($eventId) ?>;
    var fetchUrl = (typeof baseurl !== 'undefined' ? baseurl : '') +
                   '/events/viewEventStats/' + eventId;

    var PALETTE = [
        '#3B82F6','#10B981','#F59E0B','#EF4444','#8B5CF6',
        '#EC4899','#14B8A6','#F97316','#6366F1','#84CC16',
        '#06B6D4','#E11D48'
    ];

    var loaded = false;

    function loadStats() {
        if (loaded) { return; }
        loaded = true;
        fetch(fetchUrl)
            .then(function (r) { return r.json(); })
            .then(function (stats) {
                renderCharts(stats);
                updatePill(uid + '-attachments', stats.attachments);
                updatePill(uid + '-analyst-datas',     stats.analyst_datas);
            })
            .catch(function () {
                document.getElementById(uid + '-charts').innerHTML =
                    '<div class="col-12 text-center text-muted small py-2">'
                    + '<i class="fas fa-exclamation-triangle me-1"></i>'
                    + <?= json_encode(__('Could not load statistics.')) ?>
                    + '</div>';
            });
    }

    loadStats();

    /* ---- Update a pill value S ---- */
    function updatePill(pillId, value) {
        var el = document.getElementById(pillId + '-value');
        if (el) { el.textContent = value !== undefined ? value : '—'; }
    }

    /* ---- Render donut charts ---- */
    function renderCharts(stats) {
        var chartsRow = document.getElementById(uid + '-charts');
        if (!chartsRow) { return; }
        chartsRow.innerHTML = '';

        var chartDefs = [
            {
                key:    'objects',
                tab:    '#tab-objects',
                title:  <?= json_encode(__('Objects')) ?>,
                total:  stats.objects.total,
                data:   stats.objects.by_name,
                icon:   'misp-icon misp-icon-object misp-hexagone',
                color:  '#524948',
                empty:  <?= json_encode(__('No objects')) ?>
            },
            {
                key:    'attributes',
                tab:    '#tab-attributes',
                title:  <?= json_encode(__('Attributes')) ?>,
                total:  stats.attributes.total,
                data:   stats.attributes.by_category,
                icon:   'misp-icon misp-icon-attribute misp-hexagone',
                color:  '#97CC04',
                empty:  <?= json_encode(__('No attributes')) ?>
            }
        ];

        chartDefs.forEach(function (def, idx) {
            var col = document.createElement('div');
            col.className = 'col-md-6';

            if (!def.total) {
                col.innerHTML =
                    '<div class="d-flex align-items-center justify-content-center'
                    + ' h-100 text-muted py-4 gap-2">'
                    + '<i class="' + def.icon + ' opacity-50"></i>'
                    + '<span class="small">' + def.empty + '</span>'
                    + '</div>';
                chartsRow.appendChild(col);
                return;
            }

            var labels = Object.keys(def.data);
            var values = Object.values(def.data);
            var colors = labels.map(function (_, i) {
                return PALETTE[i % PALETTE.length];
            });

            var canvasId = uid + '-chart-' + def.key;

            col.innerHTML =
                '<div class="d-flex flex-column h-100">'
                + '<a class="d-flex align-items-center text-muted small text-uppercase text-decoration-none fw-bold mb-3" href="' + (typeof baseurl !== 'undefined' ? baseurl : '') + '/events/view2/' + eventId + def.tab + '">'
                + '<i class="' + def.icon + ' fs-3" style="color:' + def.color + '"></i>'
                + def.title
                + '</a>'
                + '<div class="d-flex align-items-center gap-4 flex-wrap">'

                /* Donut + center label */
                + '<div class="position-relative flex-shrink-0" style="width:140px;height:140px;">'
                + '<canvas id="' + canvasId + '"></canvas>'
                + '<div class="position-absolute top-50 start-50 translate-middle text-center lh-1">'
                + '<div class="fw-bold fs-4">' + def.total + '</div>'
                + '<div class="text-muted" style="font-size:.65rem;text-transform:uppercase;">'
                + <?= json_encode(__('total')) ?>
                + '</div>'
                + '</div>'
                + '</div>'

                /* Legend */
                + '<div class="flex-fill" style="min-width:0;">'
                + '<ul class="list-unstyled mb-0 small">'
                + labels.map(function (lbl, i) {
                    var pct = def.total > 0
                        ? Math.round(values[i] / def.total * 100) : 0;
                    return '<li class="d-flex align-items-center gap-2 mb-1">'
                        + '<span class="rounded-circle flex-shrink-0"'
                        + ' style="width:10px;height:10px;background:'
                        + colors[i] + ';display:inline-block;"></span>'
                        + '<span class="text-truncate flex-fill"'
                        + ' title="' + escapeHtml(lbl) + '">' + escapeHtml(lbl) + '</span>'
                        + '<span class="text-muted ms-1 flex-shrink-0">'
                        + values[i] + ' <span class="opacity-50">(' + pct + '%)</span>'
                        + '</span>'
                        + '</li>';
                }).join('')
                + '</ul>'
                + '</div>'

                + '</div>'
                + '</div>';

            chartsRow.appendChild(col);

            /* Init Chart.js doughnut */
            function tryChart() {
                if (typeof Chart === 'undefined') {
                    setTimeout(tryChart, 100);
                    return;
                }
                var ctx = document.getElementById(canvasId);
                if (!ctx) { return; }
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels:   labels,
                        datasets: [{
                            data:            values,
                            backgroundColor: colors,
                            borderWidth:     2,
                            hoverOffset:     4
                        }]
                    },
                    options: {
                        cutout:     '68%',
                        responsive:  true,
                        plugins: {
                            legend:  { display: false },
                            tooltip: {
                                callbacks: {
                                    label: function (ctx) {
                                        var v = ctx.raw;
                                        var pct = def.total > 0
                                            ? Math.round(v / def.total * 100) : 0;
                                        return ' ' + v + ' (' + pct + '%)';
                                    }
                                }
                            }
                        }
                    }
                });
            }
            tryChart();
        });
    }
}());
</script>