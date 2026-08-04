<?php
$event    = $data['Event']      ?? [];
$org      = $data['Org']        ?? [];
$orgc     = $data['Orgc']       ?? [];
$threat   = $data['ThreatLevel'] ?? [];
$sg       = $data['SharingGroup'] ?? [];
$eventTags= $data['EventTag']  ?? [];
$user     = $data['User']       ?? [];

$analysisMap = [
    0 => ['label' => __('Initial'),   'color' => 'secondary', 'icon' => 'fa-seedling', 'dot' => '#0d6efd'],
    1 => ['label' => __('Ongoing'),   'color' => 'warning',   'icon' => 'fa-spinner',  'dot' => '#fd7e14'],
    2 => ['label' => __('Completed'), 'color' => 'success',   'icon' => 'fa-check',    'dot' => '#198754'],
];

$threatMap = [
    0 => ['label' => __('Low'),       'color' => '#ffc107', 'icon' => 'fa-minus-circle'],
    1 => ['label' => __('Medium'),    'color' => '#fd7e14', 'icon' => 'fa-exclamation-triangle'],
    2 => ['label' => __('High'),      'color' => '#dc3545', 'icon' => 'fa-exclamation-circle'],
    3 => ['label' => __('Undefined'), 'color' => '#41464b', 'icon' => 'fa-question-circle'],
];

$analysisLevel  = (int)($event['analysis']        ?? 0);
// Backend: 1=High, 2=Medium, 3=Low, 4=Undefined
// Map to display index: 0=Low, 1=Medium, 2=High, 3=Undefined
$threatLevelId  = (int)($event['threat_level_id'] ?? 4);
$threatLevel    = [1 => 2, 2 => 1, 3 => 0, 4 => 3][$threatLevelId] ?? 3;
$distribution   = (int)($event['distribution']    ?? 0);
$isPublished    = !empty($event['published']);
$disableCorrel  = !empty($event['disable_correlation']);

$analysis = $analysisMap[$analysisLevel]  ?? $analysisMap[0];
$threat   = $threatMap[$threatLevel]    ?? $threatMap[3];

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

<div class="card mb-3 shadow-sm">
    <div class="card-body">

        <!-- ── EVENT REPORT PREVIEW ──────────────────────────── -->
        <?php
        $erReportData  = $data['EventReport'] ?? [];
        $erContent     = $erReportData['content'] ?? '';
        $erHasReport   = !empty($erReportData);
        $erCardId      = 'er-general-card';
        $erBodyId      = 'er-general-body';
        $erOverlayId   = 'er-general-overlay';
        $erMaxH        = '300px';
        $erCanAddReport = $this->Acl->canModifyEvent($data);
        ?>
        <div class="mb-4">

            <?php if ($erHasReport): ?>
                <div class="border rounded-3 position-relative"
                     id="<?= h($erCardId) ?>"
                     style="max-height:<?= $erMaxH ?>;overflow:hidden;">
                    <div class="p-3">
                        <div id="<?= h($erBodyId) ?>" class="markdown-preview-body"></div>
                    </div>
                    <div id="<?= h($erOverlayId) ?>"
                         class="position-absolute bottom-0 start-0 end-0"
                         style="display:none;">
                        <div style="height:60px;
                                    background:linear-gradient(to bottom,transparent,var(--bs-card-bg,#fff));
                                    pointer-events:none;"></div>
                        <div class="text-center py-1"
                             style="background:var(--bs-card-bg,#fff);">
                            <a href="#"
                               class="small text-muted text-decoration-none"
                               onclick="erPreviewToggle(this,'<?= h($erCardId) ?>','<?= h($erOverlayId) ?>','<?= $erMaxH ?>');return false;">
                               <i class="fas fa-chevron-down me-1"></i>
                                <?= __('Show full content') ?>
                            </a>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="border rounded-3 d-flex flex-column align-items-center
                            justify-content-center text-muted py-4">
                    <span class="misp-icon misp-icon-report misp-hexagone mb-2 opacity-50" style="font-size:2em;"></span>
                    <p class="mb-1 fw-semibold small">
                        <?= __("This event doesn't have a report for the moment") ?>
                    </p>
                    <?php if ($erCanAddReport): ?>
                        <p class="small mb-0">
                            <a href="<?= h($baseurl . '/event_reports/add/' . ($data['Event']['id'] ?? '')) ?>"
                               onclick="event.preventDefault(); openModal('<?= h($baseurl . '/event_reports/add/' . ($data['Event']['id'] ?? '')) ?>');">
                                   <?= __('Create the first report') ?>
                            </a>
                        </p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

        </div>

        <!-- ── PRIMARY: Identifiers + Creator ───────────────── -->
        <div class="row g-3 mb-3">

            <!-- ID + UUID -->
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
                                #<?= h($event['id'] ?? '') ?>
                            </span>
                        </div>
                        <div class="d-flex align-items-center gap-2">
                            <span class="text-muted small fw-bold flex-shrink-0">UUID</span>
                            <div class="d-inline-flex align-items-center gap-1 bg-light border rounded px-2 py-1">
                                <span class="font-monospace small text-truncate"><?= h($event['uuid'] ?? '') ?></span>
                                <button
                                    class="text-muted border-0 bg-transparent p-0 ms-1 flex-shrink-0"
                                    onclick="copyToClipboard(this, '<?= h($event['uuid'] ?? '') ?>')"
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
                    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 py-1">
                        <div class="d-inline-flex align-items-center gap-2">
                            <?php $logo = $this->OrgImg->getOrgLogoV2($orgc, 24); ?>
                            <?= $logo !== '' ? $logo : '<i class="misp-icon misp-icon-organisation misp-simple text-muted"></i>' ?>
                            <a href="<?= h($baseurl . '/organisations/view/' . $orgc['id']) ?>" 
                               class="text-decoration-none fw-semibold text-primary"><?= h($orgc['name'] ?? '') ?>
                            </a>
                        </div>
                        <div class="d-flex align-items-center gap-2 text-muted small">
                            <?php $email = h($user['email'] ?? '') ?>
                            <?= $email !== '' ? '<span><i class="misp-icon misp-icon-user1 misp-simple"></i>' . $email . '</span>'  : '' ?>
                        </div>
                    </div>
                </div>
            </div>

        </div>

        <!-- ── PRIMARY: Distribution + Publication ─────────── -->
        <div class="row g-3 mb-4">

            <!-- DISTRIBUTION + SHARING GROUP -->
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
                        <?php if ($distribution === 4 && !empty($sg)): ?>
                            <a href="<?= h($baseurl . '/sharing_groups/view/' . ($sg['id'] ?? '')) ?>"
                            class="d-inline-flex align-items-center gap-1 text-decoration-none small">
                                <span class="misp-icon misp-icon-sharing-group misp-hexagone text-primary"></span>
                                <?= h($sg['name'] ?? '') ?>
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- PUBLICATION: status + dates -->
            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <i class="fas fa-paper-plane me-1"></i>
                        <?= __('Publication') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between mb-2">
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
                        <?php if ($isPublished && !empty($event['first_publication'])): ?>
                            <div class="d-flex align-items-center gap-1 text-muted small">
                                <i class="fas fa-flag fa-fw"></i>
                                <span class="fw-medium"><?= __('First:') ?></span>
                                <?= $this->Time->time($event['first_publication']) ?>
                            </div>
                        <?php endif; ?>
                        <?php if ($isPublished && !empty($event['publish_timestamp'])): ?>
                            <div class="d-flex align-items-center gap-1 text-muted small">
                                <i class="fas fa-history fa-fw"></i>
                                <span class="fw-medium"><?= __('Last:') ?></span>
                                <?= $this->Time->time($event['publish_timestamp']) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

        </div>

        <!-- ── SECONDARY ─────────────────────────────────────── -->

        <div class="row g-2 align-items-start mb-3">

            <!-- ANALYSIS -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-2">
                    <?= __('Analysis') ?>
                </div>
                <?php $analysisPct = (int)(($analysisLevel + 1) / 3 * 100); ?>
                <div class="d-flex align-items-center gap-2">
                    <div class="flex-fill" style="height:4px;border-radius:2px;background:#e9ecef;overflow:hidden;">
                        <div style="height:100%;width:<?= $analysisPct ?>%;border-radius:2px;background:<?= h($analysis['dot']) ?>;"></div>
                    </div>
                    <span class="small fw-semibold flex-shrink-0" style="color:<?= h($analysis['dot']) ?>;"><?= h($analysis['label']) ?></span>
                </div>
            </div>

            <!-- THREAT LEVEL -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-2">
                    <?= __('Threat Level') ?>
                </div>
                <?php $threatPct = $threatLevel < 3 ? (int)(($threatLevel + 1) / 3 * 100) : 5; ?>
                <div class="d-flex align-items-center gap-2">
                    <div class="flex-fill" style="height:4px;border-radius:2px;background:#e9ecef;overflow:hidden;">
                        <div style="height:100%;width:<?= $threatPct ?>%;border-radius:2px;background:<?= h($threat['color']) ?>;"></div>
                    </div>
                    <span class="small fw-semibold flex-shrink-0" style="color:<?= h($threat['color']) ?>;"><?= h($threat['label']) ?></span>
                </div>
            </div>

            <!-- CORRELATION -->
            <div class="col-md-2">
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

            <!-- STATUS: LOCKED + PROTECTED -->
            <div class="col-md-3">
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

            <!-- EXTENDS UUID -->
            <?php if (!empty($event['extends_uuid'])): ?>
            <div class="col-12">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Extends Event') ?>
                </div>
                <a href="<?= h($baseurl . '/events/view/' . $event['extends_uuid']) ?>"
                   class="font-monospace small text-decoration-none">
                    <i class="fas fa-code-branch me-1 text-muted"></i>
                    <?= h($event['extends_uuid']) ?>
                </a>
            </div>
            <?php endif; ?>

        </div>

        <!--  STATISTICS  -->
        <?php
        $eventId = h($event['id'] ?? '');
        $statsUid = 'evtstats-' . $eventId;

        /* Counts available immediately from already-loaded data */
        $tagCount = count(array_filter(
            $eventTags, fn($et) => empty($et['Tag']['is_galaxy'])
        ));
        $clusterCount = 0;
        foreach ($data['Galaxy'] ?? [] as $gal) {
            $clusterCount += count($gal['GalaxyCluster'] ?? []);
        }
        ?>

        <hr class="my-4">

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

                <!-- Reports  -->
                <div class="col-6 col-md-3">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon'  => 'misp-icon misp-icon-report misp-simple',
                        'color' => '#4DA167',
                        'label' => __('Reports'),
                        'value' => null,
                        'id'    => $statsUid . '-reports',
                        'onclick' => "window.scrollTo({top: document.getElementById('report-card').offsetTop - window.innerHeight * 0.1, behavior:'smooth'});",
                    ]); ?>
                </div>

            </div>

        </div>

    </div>
</div>

<?php if ($erHasReport): ?>
    <script>
    (function () {
        var raw       = <?= json_encode($erContent) ?>;
        var bodyId    = <?= json_encode($erBodyId) ?>;
        var cardId    = <?= json_encode($erCardId) ?>;
        var overlayId = <?= json_encode($erOverlayId) ?>;
        var maxH      = <?= json_encode($erMaxH) ?>;

        function checkOverflow() {
            var card    = document.getElementById(cardId);
            var overlay = document.getElementById(overlayId);
            if (!card || !overlay) { return; }
            if (card.scrollHeight > card.offsetHeight + 4) {
                overlay.style.display = 'block';
            }
        }

        document.addEventListener('DOMContentLoaded', function () {
            var target = document.getElementById(bodyId);
            if (!target) { return; }
            function render() {
                if (window.markdownit) {
                    var md = window.markdownit({
                        html: false, linkify: true, typographer: true
                    });
                    target.innerHTML = md.render(raw);
                    checkOverflow();
                } else {
                    setTimeout(render, 100);
                }
            }
            render();
        });

        if (typeof erPreviewToggle === 'undefined') {
            window.erPreviewToggle = function (link, cId, oId, mH) {
                var card     = document.getElementById(cId);
                var overlay  = document.getElementById(oId);
                var gradient = overlay.querySelector('div');
                var icon     = link.querySelector('i');
                var expanded = card.dataset.erExpanded === '1';
                if (expanded) {
                    card.style.maxHeight    = mH;
                    card.style.overflow     = 'hidden';
                    card.dataset.erExpanded = '0';
                    gradient.style.display  = '';
                    icon.className = 'fas fa-chevron-down me-1';
                    link.lastChild.textContent = ' <?= __('Show full content') ?>';
                } else {
                    card.style.maxHeight    = 'none';
                    card.style.overflow     = 'visible';
                    card.dataset.erExpanded = '1';
                    gradient.style.display  = 'none';
                    icon.className = 'fas fa-chevron-up me-1';
                    link.lastChild.textContent = ' <?= __('Collapse') ?>';
                }
            };
        }
    }());
    </script>
<?php endif; ?>

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

    fetch(fetchUrl)
        .then(function (r) { return r.json(); })
        .then(function (stats) {
            renderCharts(stats);
            updatePill(uid + '-attachments', stats.attachments);
            updatePill(uid + '-reports',     stats.reports);
        })
        .catch(function () {
            document.getElementById(uid + '-charts').innerHTML =
                '<div class="col-12 text-center text-muted small py-2">'
                + '<i class="fas fa-exclamation-triangle me-1"></i>'
                + <?= json_encode(__('Could not load statistics.')) ?>
                + '</div>';
        });

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
                        + ' title="' + lbl + '">' + lbl + '</span>'
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