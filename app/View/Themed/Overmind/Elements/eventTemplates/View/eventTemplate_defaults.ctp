<?php
/**
 * What an event created from this template inherits before the reporter types
 * anything: `event_defaults` in the definition. The raw values live in the
 * Definition tab — this card spells them out.
 */
$tpl = $data['EventTemplate'] ?? [];
$definition = is_array($tpl['definition'] ?? null) ? $tpl['definition'] : [];
$defaults = is_array($definition['event_defaults'] ?? null)
    ? $definition['event_defaults']
    : [];

$analysisMap = [
    0 => ['label' => __('Initial'), 'color' => 'secondary', 'icon' => 'fa-seedling'],
    1 => ['label' => __('Ongoing'), 'color' => 'warning', 'icon' => 'fa-spinner'],
    2 => ['label' => __('Completed'), 'color' => 'success', 'icon' => 'fa-check'],
];
// Backend threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined.
$threatMap = [
    1 => ['label' => __('High'), 'color' => '#dc3545', 'icon' => 'fa-exclamation-circle'],
    2 => ['label' => __('Medium'), 'color' => '#fd7e14', 'icon' => 'fa-exclamation-triangle'],
    3 => ['label' => __('Low'), 'color' => '#ffc107', 'icon' => 'fa-minus-circle'],
    4 => ['label' => __('Undefined'), 'color' => '#41464b', 'icon' => 'fa-question-circle'],
];

$infoTemplate = (string)($defaults['info_template'] ?? '');
$hasDistribution = array_key_exists('distribution', $defaults);
$analysis = array_key_exists('analysis', $defaults)
    ? ($analysisMap[(int)$defaults['analysis']] ?? null)
    : null;
$threat = array_key_exists('threat_level_id', $defaults)
    ? ($threatMap[(int)$defaults['threat_level_id']] ?? null)
    : null;
$defaultTags = is_array($defaults['tags'] ?? null) ? $defaults['tags'] : [];
?>
<div class="card mb-3 shadow-sm">
    <div class="card-header bg-white fw-semibold d-flex align-items-center">
        <i class="misp-icon misp-icon-event misp-simple me-2 text-event"></i>
        <?= __('Event defaults') ?>
    </div>
    <div class="card-body p-4">

        <?php if (empty($defaults)): ?>
            <div class="text-muted fst-italic">
                <?= __('None — an event created from this template starts with your instance defaults.') ?>
            </div>
        <?php else: ?>

            <!-- INFO TEMPLATE -->
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Event info pattern') ?></div>
                <?php if ($infoTemplate !== ''): ?>
                    <div class="bg-light border rounded px-3 py-2 font-monospace" style="font-size:.85rem;">
                        <?= h($infoTemplate) ?>
                    </div>
                    <div class="d-flex align-items-center gap-1 mt-1 text-muted" style="font-size:.75rem;">
                        <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                        <?= __('%s placeholders are replaced with what the reporter fills in.', '<code>{{…}}</code>') ?>
                    </div>
                <?php else: ?>
                    <div class="text-muted">&mdash;</div>
                <?php endif; ?>
            </div>

            <div class="row g-3">

                <!-- DISTRIBUTION -->
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Distribution') ?></div>
                    <div class="py-1">
                        <?php if ($hasDistribution): ?>
                            <?= $this->element('genericElementsBS5/Badges/distribution', [
                                'distribution' => (int)$defaults['distribution'],
                                'full' => true,
                            ]) ?>
                        <?php else: ?>
                            <span class="text-muted"><?= __('Instance default') ?></span>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- THREAT LEVEL -->
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Threat level') ?></div>
                    <div class="py-1">
                        <?php if ($threat !== null): ?>
                            <span class="badge d-inline-flex align-items-center gap-1 px-2 py-1"
                                  style="background:<?= h($threat['color']) ?>1a;
                                         color:<?= h($threat['color']) ?>;
                                         border:1px solid <?= h($threat['color']) ?>40;">
                                <i class="fas <?= h($threat['icon']) ?>"></i>
                                <?= h($threat['label']) ?>
                            </span>
                        <?php else: ?>
                            <span class="text-muted"><?= __('Instance default') ?></span>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- ANALYSIS -->
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Analysis') ?></div>
                    <div class="py-1">
                        <?php if ($analysis !== null): ?>
                            <span class="badge bg-<?= h($analysis['color']) ?>-subtle
                                         text-<?= h($analysis['color']) ?>-emphasis
                                         border border-<?= h($analysis['color']) ?>-subtle
                                         d-inline-flex align-items-center gap-1">
                                <i class="fas <?= h($analysis['icon']) ?>"></i>
                                <?= h($analysis['label']) ?>
                            </span>
                        <?php else: ?>
                            <span class="text-muted"><?= __('Instance default') ?></span>
                        <?php endif; ?>
                    </div>
                </div>

            </div>

            <!-- TAGS -->
            <div class="mt-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Tags applied to the new event') ?></div>
                <?php if (!empty($defaultTags)): ?>
                    <div class="d-inline-flex flex-wrap align-items-center">
                        <?php foreach ($defaultTags as $defaultTag): ?>
                            <?php
                            $tagName = is_array($defaultTag)
                                ? ($defaultTag['name'] ?? '')
                                : (string)$defaultTag;
                            if ($tagName === '') {
                                continue;
                            }
                            echo $this->element('genericElementsBS5/Badges/tag', [
                                'tag' => ['name' => $tagName],
                                'local' => !empty($defaultTag['local']),
                                'hiddenClass' => null,
                                'showFavourite' => false,
                            ]);
                            ?>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="text-muted"><?= __('None') ?></div>
                <?php endif; ?>
            </div>

        <?php endif; ?>

    </div>
</div>
