<?php
/*
 * Landing page for /analystData/index (no type): lets the user choose which
 * analyst data index to open, with a per-type record count.
 */

$this->set('headerTitle', __('Analyst Data'));
$this->set('headerDescription', __('Notes, opinions and relationships enriching your MISP data. Pick a collection to explore.'));

$types = [
    'Note' => [
        'icon'        => 'misp-icon misp-icon-analyst-note misp-simple',
        'color'       => 'primary',
        'title'       => __('Notes'),
        'description' => __('Free-text annotations attached to any MISP data point.'),
    ],
    'Opinion' => [
        'icon'        => 'misp-icon misp-icon-analyst-opinion misp-simple',
        'color'       => 'success',
        'title'       => __('Opinions'),
        'description' => __('Confidence ratings (0–100) with a short justification.'),
    ],
    'Relationship' => [
        'icon'        => 'fas fa-diagram-project',
        'color'       => 'correlation',
        'title'       => __('Relationships'),
        'description' => __('Typed links connecting two MISP data points together.'),
    ],
];

$selectedType = $selectedType ?? null;
if (!isset($types[$selectedType])) {
    $selectedType = null;
}


if (!empty($selectedType) && !empty($me['Role']['perm_analyst_data'])) {
    $this->set('headerActions', [
        [
            'type'  => 'modal',
            'label' => __('Add %s', $selectedType),
            'icon'  => 'plus',
            'class' => 'btn btn-' . $types[$selectedType]['color'],
            'url'   => $baseurl . '/analystData/add/' . $selectedType,
        ],
    ]);
}
?>

<div class="container-fluid">
    <div class="row g-4">
        <?php foreach ($types as $type => $meta): ?>
            <?php
                $count = isset($counts[$type]) ? (int)$counts[$type] : 0;
                $color = h($meta['color']);
                $isActive = ($type === $selectedType);
                $url = $isActive
                    ? $baseurl . '/analystData/index'
                    : $baseurl . '/analystData/index/' . $type;
            ?>
            <div class="col-12 col-md-4">
                <div class="card h-100 shadow-sm border-0 border-start border-4 border-<?= $color ?> analyst-hub-card position-relative <?= $isActive ? 'analyst-hub-card-active' : '' ?>">
                    <div class="card-body d-flex flex-column p-4">

                        <div class="d-flex align-items-center justify-content-between mb-3">
                            <span class="d-inline-flex align-items-center justify-content-center rounded-3 bg-<?= $color ?> bg-opacity-10 text-<?= $color ?>"
                                  style="width:3rem; height:3rem; font-size:1.35rem;">
                                <i class="<?= h($meta['icon']) ?>"></i>
                            </span>
                            <span class="badge rounded-pill bg-<?= $color ?> fw-semibold px-3 py-2" style="font-size:0.9rem;">
                                <?= number_format($count, 0, ',', ' ') ?>
                            </span>
                        </div>

                        <h2 class="h4 fw-bold mb-1"><?= h($meta['title']) ?></h2>
                        <p class="text-muted mb-4" style="font-size:0.9rem;">
                            <?= h($meta['description']) ?>
                        </p>

                        <div class="mt-auto">
                            <a href="<?= h($url) ?>"
                               class="btn <?= $isActive ? 'btn-' . $color : 'btn-outline-' . $color ?> fw-semibold d-inline-flex align-items-center gap-2 stretched-link">
                                <?php if ($isActive): ?>
                                    <i class="fas fa-check"></i>
                                    <?= __('Viewing') ?>
                                <?php else: ?>
                                    <?= __('Open') ?>
                                    <i class="fas fa-arrow-right"></i>
                                <?php endif; ?>
                            </a>
                        </div>

                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<?php if (!empty($selectedType)): ?>
    <!-- The active tab-pane makes the layout's lazy loader fetch this fragment on load. -->
    <div class="mt-4">
        <div class="tab-content">
            <div class="tab-pane active" role="tabpanel">
                <div id="adIndexContainer" class="ajax-tab-content"
                    data-url="<?= h($baseurl . '/analystData/index/' . $selectedType) ?>">
                    <div class="text-center p-4"><div class="spinner-border"></div></div>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>