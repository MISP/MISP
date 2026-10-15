<?php
/**
 * What an event created from this template starts with before the reporter
 * types anything: `event_defaults` in the definition. Analysis and threat
 * level use the event view's own scales, so a default reads the same as the
 * event it produces.
 */
$tpl = $data['EventTemplate'] ?? [];
$definition = is_array($tpl['definition'] ?? null) ? $tpl['definition'] : [];
$defaults = is_array($definition['event_defaults'] ?? null) ? $definition['event_defaults'] : [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$analysisStops = [
    ['value' => 0, 'title' => __('Initial'),   'tone' => '#0d6efd', 'sub' => __('Raw intelligence')],
    ['value' => 1, 'title' => __('Ongoing'),   'tone' => '#fd7e14', 'sub' => __('Under investigation')],
    ['value' => 2, 'title' => __('Completed'), 'tone' => '#198754', 'sub' => __('Verified & closed')],
];
$threatStops = [
    ['value' => 4, 'title' => __('Undefined'), 'tone' => '#41464b', 'sub' => __('No risk')],
    ['value' => 3, 'title' => __('Low'),       'tone' => '#ffc107', 'sub' => __('Opportunistic')],
    ['value' => 2, 'title' => __('Medium'),    'tone' => '#fd7e14', 'sub' => __('Targeted campaign')],
    ['value' => 1, 'title' => __('High'),      'tone' => '#dc3545', 'sub' => __('Active exploitation')],
];

$infoTemplate = (string)($defaults['info_template'] ?? '');
$defaultTags = is_array($defaults['tags'] ?? null) ? $defaults['tags'] : [];
$defaultClusters = is_array($defaults['galaxy_clusters'] ?? null) ? $defaults['galaxy_clusters'] : [];
$instanceDefault = '<span class="small text-body-secondary fst-italic">' . __('Instance default') . '</span>';
?>
<div class="card mb-3 shadow-sm">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0"
                 style="width:36px;height:36px;background:rgba(var(--bs-event-rgb),.12);color:rgb(var(--bs-event-rgb));">
                <i class="misp-icon misp-icon-event misp-simple"></i>
            </div>
            <div>
                <div class="fw-bold lh-1"><?= __('Event defaults') ?></div>
                <div class="small text-muted mt-1"><?= __('What an event created from this template starts with') ?></div>
            </div>
        </div>
    </div>
    <div class="card-body py-3 d-flex flex-column gap-3">

        <?php if (empty($defaults)): ?>
            <span class="text-body-secondary fst-italic small">
                <?= __('None — an event created from this template starts with your instance defaults.') ?>
            </span>
        <?php else: ?>

            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Event info') ?></div>
                <?php if ($infoTemplate !== ''): ?>
                    <?php
                    /* The {{…}} placeholders stand out from the fixed text. */
                    $pattern = preg_replace(
                        '/\{\{(.*?)\}\}/',
                        '<span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-normal">$1</span>',
                        h($infoTemplate)
                    );
                    ?>
                    <div class="border rounded-3 bg-body-tertiary px-3 py-2 d-flex flex-wrap align-items-center gap-1"><?= $pattern ?></div>
                    <div class="small text-body-secondary mt-1"><?= __('The highlighted parts are filled from the date and what the reporter enters.') ?></div>
                <?php else: ?>
                    <?= $instanceDefault ?>
                <?php endif; ?>
            </div>

            <div class="row g-4">
                <div class="col-12 col-md-6">
                    <div class="<?= $labelClass ?> mb-2" style="<?= $labelStyle ?>"><?= __('Analysis') ?></div>
                    <?php if (array_key_exists('analysis', $defaults)): ?>
                        <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                            'field' => 'default_analysis',
                            'value' => (int)$defaults['analysis'],
                            'options' => $analysisStops,
                            'readonly' => true,
                        ]) ?>
                    <?php else: ?>
                        <?= $instanceDefault ?>
                    <?php endif; ?>
                </div>
                <div class="col-12 col-md-6">
                    <div class="<?= $labelClass ?> mb-2" style="<?= $labelStyle ?>"><?= __('Threat Level') ?></div>
                    <?php if (array_key_exists('threat_level_id', $defaults)): ?>
                        <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                            'field' => 'default_threat_level_id',
                            'value' => (int)$defaults['threat_level_id'],
                            'options' => $threatStops,
                            'readonly' => true,
                        ]) ?>
                    <?php else: ?>
                        <?= $instanceDefault ?>
                    <?php endif; ?>
                </div>
            </div>

            <div class="row g-3">
                <div class="col-12 col-md-5">
                    <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Distribution') ?></div>
                    <?php if (array_key_exists('distribution', $defaults)): ?>
                        <?php $level = $this->DistributionLevel->get($defaults['distribution']); ?>
                        <div class="d-flex align-items-center gap-2 min-w-0">
                            <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                                  style="<?= $tileStyle ?>background:<?= h($this->DistributionLevel->themed($level, 'bg')) ?>;color:<?= h($this->DistributionLevel->themed($level, 'fg')) ?>;">
                                <i class="<?= h($level['icon']) ?>"></i>
                            </span>
                            <div class="min-w-0">
                                <div class="fw-semibold lh-sm"><?= h($level['label']) ?></div>
                                <div class="small text-body-secondary text-truncate"><?= h($level['sub']) ?></div>
                            </div>
                        </div>
                    <?php else: ?>
                        <?= $instanceDefault ?>
                    <?php endif; ?>
                </div>
                <div class="col-12 col-md-7">
                    <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= h(__('Tags & clusters applied')) ?></div>
                    <?php
                    $tagBadges = '';
                    foreach ($defaultTags as $defaultTag) {
                        $tagName = is_array($defaultTag) ? ($defaultTag['name'] ?? '') : (string)$defaultTag;
                        if ($tagName === '') {
                            continue;
                        }
                        $tagBadges .= '<span class="d-inline-flex align-items-center gap-1">'
                            . $this->element('genericElementsBS5/Badges/tag', [
                                'tag' => ['name' => $tagName],
                                'local' => false,
                                'hiddenClass' => null,
                                'showFavourite' => false,
                            ])
                            . (!empty($defaultTag['locked'])
                                ? '<i class="fas fa-lock fa-xs text-body-secondary" title="' . h(__('Locked by the template')) . '"></i>'
                                : '')
                            . '</span>';
                    }
                    foreach ($defaultClusters as $cluster) {
                        if (empty($cluster['value'])) {
                            continue;
                        }
                        $tagBadges .= '<span class="badge rounded-pill fw-normal d-inline-flex align-items-center gap-1"'
                            . ' style="background:rgba(var(--bs-galaxy-rgb),.12);color:rgb(var(--bs-galaxy-rgb));">'
                            . '<i class="misp-icon misp-icon-galaxy misp-simple"></i>'
                            . '<span class="opacity-75">' . h($cluster['galaxy_type'] ?? '') . '</span> ' . h($cluster['value'])
                            . (!empty($cluster['locked']) ? ' <i class="fas fa-lock fa-xs" title="' . h(__('Locked by the template')) . '"></i>' : '')
                            . '</span>';
                    }
                    ?>
                    <?php if ($tagBadges !== ''): ?>
                        <div class="d-flex flex-wrap align-items-center gap-1"><?= $tagBadges ?></div>
                    <?php else: ?>
                        <span class="small text-body-secondary fst-italic"><?= __('None') ?></span>
                    <?php endif; ?>
                </div>
            </div>

        <?php endif; ?>

    </div>
</div>
