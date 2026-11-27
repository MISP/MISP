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
    </div>
</div>
