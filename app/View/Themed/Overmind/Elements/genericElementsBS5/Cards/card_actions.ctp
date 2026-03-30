<?php
/**
 * Params :
 * - 'url' => string,
 * - 'icon' => string,
 * - 'label' => string,
 * - 'success' => bool (optional),
 * - 'danger' => bool (optional),
 * - 'onclick' => string (optional)
 */

$actions = $actions ?? [];
?>

<div class="card shadow-sm">
    <div class="card-body">
        <h5 class="fw-bold d-flex align-items-center gap-2 mb-3">
            <i class="fas fa-forward text-primary"></i>
            <?= __('Quick action') ?>
        </h5>

        <div class="d-flex flex-column gap-2">
            <?php if(!empty($actions)): ?>
                <?php foreach ($actions as $action):
                    $isSuccess = !empty($action['success']);
                    $isWarning = !empty($action['warning']);
                    $isDanger = !empty($action['danger']);
                    $url = $action['url'] ?? '#';
                    $icon = $action['icon'] ?? 'fas fa-circle';
                    $label = $action['label'] ?? '';
                    $onclick = $action['onclick'] ?? null;

                    $btnClass = 'btn-light';
                    if ($isDanger) {
                        $btnClass = 'btn-danger-subtle text-danger';
                    } elseif ($isWarning) {
                        $btnClass = 'btn-warning-subtle text-warning';
                    } elseif ($isSuccess) {
                        $btnClass = 'btn-success-subtle text-success';
                    }

                    $iconColorClass = ($isDanger || $isWarning || $isSuccess) ? '' : 'text-secondary';
                    $chevronColorClass = ($isDanger || $isWarning  || $isSuccess) ? '' : 'text-muted';
                ?>

                    <a class="quick-action btn <?= $btnClass ?> d-flex align-items-center justify-content-between rounded-4 py-3 px-3"
                    href="<?= h($url) ?>"
                    <?= $onclick ? 'onclick="' . $onclick . '"' : '' ?>>

                        <span class="d-flex align-items-center gap-3">
                            <i class="<?= h($icon) ?> <?= $iconColorClass ?>"></i>
                            <?= h($label) ?>
                        </span>

                        <i class="fas fa-chevron-right <?= $chevronColorClass ?>"></i>
                    </a>

                <?php endforeach; ?>
            <?php else: ?>
                <p class="mb-0">No action available for you</p>
            <?php endif; ?>

        </div>
    </div>
</div>