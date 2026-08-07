<?php
/**
 * Overall health of the instance, as four cards sitting between the page
 * header and the settings tabs.
 *
 * Params:
 *  - issues            array from ServersController::serverSettings()
 *  - diagnostic_errors int
 */

$cards = array(
    array(
        'label' => __('Critical settings'),
        'value' => (int)$issues['errors'][0]['value'],
        'description' => $issues['errors'][0]['description'],
        'icon' => 'triangle-exclamation',
        'accent' => 'var(--bs-danger)',
    ),
    array(
        'label' => __('Recommended settings'),
        'value' => (int)$issues['errors'][1]['value'],
        'description' => $issues['errors'][1]['description'],
        'icon' => 'circle-exclamation',
        'accent' => 'var(--bs-warning)',
    ),
    array(
        'label' => __('Optional settings'),
        'value' => (int)$issues['errors'][2]['value'],
        'description' => $issues['errors'][2]['description'],
        'icon' => 'circle-info',
        'accent' => 'var(--bs-success)',
    ),
    array(
        'label' => __('Critical issues'),
        'value' => (int)$diagnostic_errors,
        'description' => __('Issues revealed here can be due to incorrect directory permissions or not correctly installed dependencies.'),
        'icon' => 'stethoscope',
        'accent' => 'var(--bs-secondary)',
    ),
);
?>
<div class="container-fluid ss-scope">
    <div class="row g-3 mb-4">
        <?php foreach ($cards as $card): ?>
            <?php $healthy = $card['value'] === 0; ?>
            <div class="col-12 col-sm-6 col-xl-3">
                <div class="card shadow-sm h-100 ss-health-card"
                     style="--ss-accent: <?= h($card['accent']) ?>;">
                    <div class="card-body p-3">

                        <div class="d-flex justify-content-between align-items-start mb-3">
                            <span class="ss-health-icon">
                                <i class="fas fa-<?= h($card['icon']) ?>"></i>
                            </span>
                            <span class="badge rounded-pill text-uppercase <?= $healthy ? 'text-bg-success' : 'text-bg-warning' ?>"
                                  style="letter-spacing:.06em;">
                                <?= $healthy ? __('Healthy') : __('Warning') ?>
                            </span>
                        </div>

                        <div class="ss-health-eyebrow"><?= h($card['label']) ?></div>
                        <div class="ss-health-value my-1">
                            <?= h(number_format($card['value'], 0, ',', ' ')) ?>
                        </div>
                        <div class="text-muted" style="font-size:.75rem;">
                            <?= h($card['description']) ?>
                        </div>

                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>
