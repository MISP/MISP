<?php
/*
 * General metadata card for a single Analyst Data record (Note / Opinion /
 * Relationship), rendered inside the analystData/view view_layout "General" tab.
 *
 * Receives $data (the CRUD->view payload). $modelSelection / $distributionLevels
 * / $baseurl are inherited view vars set by AnalystDataController::view().
 */
$m = $modelSelection ?? 'Note';
$record = $data[$m] ?? [];

$styles = [
    'Note'         => ['color' => 'primary', 'icon' => 'misp-icon misp-icon-analyst-note misp-simple',    'label' => __('Note')],
    'Opinion'      => ['color' => 'success', 'icon' => 'misp-icon misp-icon-analyst-opinion misp-simple', 'label' => __('Opinion')],
    'Relationship' => ['color' => 'info',    'icon' => 'fas fa-diagram-project',                          'label' => __('Relationship')],
];
$s = $styles[$m] ?? $styles['Note'];
$color = $s['color'];

$objLink = function ($type, $uuid) use ($baseurl) {
    if (empty($uuid)) {
        return '<span class="text-muted">&mdash;</span>';
    }
    if (in_array($type, ['Note', 'Opinion', 'Relationship'], true)) {
        $url = $baseurl . '/analystData/view/' . $type . '/' . $uuid;
    } else {
        $url = $baseurl . '/' . Inflector::tableize($type) . '/view/' . $uuid;
    }
    return sprintf(
        '<span class="badge bg-secondary-subtle text-secondary-emphasis me-1">%s</span>'
        . '<a class="text-decoration-none font-monospace small" href="%s" title="%s">%s</a>',
        h($type), h($url), h($uuid), h($uuid)
    );
};

// Distribution: level name, or the sharing group name for "Sharing group" (4).
$dist = isset($record['distribution']) ? (int)$record['distribution'] : null;
$distName = ($dist !== null && isset($distributionLevels[$dist]))
    ? $distributionLevels[$dist]
    : ($dist === null ? '' : (string)$dist);
if ($dist === 4 && !empty($record['SharingGroup']['name'])) {
    $distName = $record['SharingGroup']['name'];
}

$opinion = isset($record['opinion']) ? max(0, min(100, (int)$record['opinion'])) : null;
if ($opinion !== null) {
    $opLabel = $opinion >= 81 ? __('Strongly Agree')
        : ($opinion >= 61 ? __('Agree')
        : ($opinion >= 41 ? __('Neutral')
        : ($opinion >= 21 ? __('Disagree') : __('Strongly Disagree'))));
    $opColor = $opinion === 50 ? 'secondary' : ($opinion > 50 ? 'success' : 'danger');
}
?>
<div class="card mb-3 shadow-sm">
    <div class="card-header bg-<?= $color ?> bg-opacity-10 d-flex align-items-center gap-2 py-3"
         style="border-bottom:2px solid var(--bs-<?= $color ?>);">
        <span class="d-inline-flex align-items-center justify-content-center rounded-3 bg-<?= $color ?> bg-opacity-10 text-<?= $color ?>"
              style="width:2.5rem; height:2.5rem; font-size:1.1rem;">
            <i class="<?= h($s['icon']) ?>"></i>
        </span>
        <div>
            <div class="fw-bold fs-5"><?= h($s['label']) ?> #<?= h($record['id'] ?? '') ?></div>
            <?php if (!empty($record['note_type_name'])): ?>
                <div class="text-muted small"><?= h($record['note_type_name']) ?></div>
            <?php endif; ?>
        </div>
    </div>
    <div class="card-body p-4">

        <!-- ── MAIN CONTENT ─────────────────────────────────────── -->
        <?php if ($m === 'Note'): ?>
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Note') ?></div>
                <div class="bg-light border rounded p-3" style="white-space:pre-wrap;"><?= h($record['note'] ?? '') ?></div>
            </div>
        <?php elseif ($m === 'Opinion'): ?>
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Opinion') ?></div>
                <?php if ($opinion !== null): ?>
                    <span class="badge bg-<?= $opColor ?>-subtle text-<?= $opColor ?>-emphasis border border-<?= $opColor ?>-subtle fw-semibold fs-6">
                        <?= h($opLabel) ?> &middot; <?= $opinion ?>/100
                    </span>
                <?php endif; ?>
            </div>
            <?php if (!empty($record['comment'])): ?>
                <div class="mb-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Comment') ?></div>
                    <div class="bg-light border rounded p-3" style="white-space:pre-wrap;"><?= h($record['comment']) ?></div>
                </div>
            <?php endif; ?>
        <?php elseif ($m === 'Relationship'): ?>
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Related object') ?></div>
                <div class="d-flex align-items-center gap-2 flex-wrap">
                    <?php if (!empty($record['relationship_type'])): ?>
                        <span class="badge bg-info-subtle text-info-emphasis border border-info-subtle">
                            <?= h($record['relationship_type']) ?>
                        </span>
                    <?php endif; ?>
                    <i class="fas fa-arrow-right text-muted"></i>
                    <?= $objLink($record['related_object_type'] ?? '', $record['related_object_uuid'] ?? '') ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- ── TARGET OBJECT ────────────────────────────────────── -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Target object') ?></div>
            <div><?= $objLink($record['object_type'] ?? '', $record['object_uuid'] ?? '') ?></div>
        </div>

        <!-- ── META GRID ────────────────────────────────────────── -->
        <div class="row g-3">

            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('UUID') ?></div>
                <div class="bg-light rounded px-2 py-1 border font-monospace small text-truncate">
                    <?= h($record['uuid'] ?? '') ?>
                </div>
            </div>

            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Distribution') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate"><?= h($distName) ?></div>
            </div>

            <?php if (!empty($record['Orgc'])): ?>
            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Creator org') ?></div>
                <div class="d-flex align-items-center bg-light rounded px-2 py-1 border">
                    <?= $this->OrgImg->getOrgLogoV2($record['Orgc'], 24) ?>
                    <span class="fw-semibold text-dark ms-2 text-truncate"><?= h($record['Orgc']['name'] ?? '') ?></span>
                </div>
            </div>
            <?php endif; ?>

            <?php if (isset($record['authors']) && $record['authors'] !== ''): ?>
            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Authors') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate"><?= h($record['authors']) ?></div>
            </div>
            <?php endif; ?>

            <?php if ($m === 'Note' && !empty($record['language'])): ?>
            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Language') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate"><?= h($record['language']) ?></div>
            </div>
            <?php endif; ?>

            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Created') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate"><?= h($record['created'] ?? '') ?></div>
            </div>

            <div class="col-md-6 col-lg-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Modified') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate"><?= h($record['modified'] ?? '') ?></div>
            </div>

        </div>

    </div>
</div>
