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


<div class="card shadow-sm mb-3">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#ccfbf1;">
                <i class="fas fa-bolt"
                   style="color:#0f766e;font-size:1rem;"></i>
            </div>
            <div class="fw-bold lh-1"><?= __('Quick action') ?></div>
        </div>
    </div>

    <!-- BODY -->
    <div class="p-3">
        <div class="d-flex flex-column gap-2">
            <?php if(!empty($actions)): ?>
                <?php foreach ($actions as $action):
                    $isSuccess = !empty($action['success']);
                    $isWarning = !empty($action['warning']);
                    $isDanger = !empty($action['danger']);
                    $url = $action['url'] ?? '#';
                    $icon = $action['icon'] ?? 'fas fa-circle';
                    $label = $action['label'] ?? '';
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

                    $innerHtml = '
                        <span class="d-flex align-items-center gap-3">
                            <i class="' . h($icon) . ' ' . $iconColorClass . '"></i>
                            ' . h($label) . '
                        </span>
                        <i class="fas fa-chevron-right ' . $chevronColorClass . '"></i>
                    ';

                    $fullBtnClass = "quick-action btn $btnClass d-flex align-items-center justify-content-between rounded-4 py-3 px-3 w-100 border-0";
                ?>
                    <?php if (isset($action['type']) && $action['type'] === 'post'): ?>
                        <?php
                            $postOptions = [
                                'escape' => false,
                                'class' => $fullBtnClass,
                                'confirm' => $action['confirm'] ?? null,
                            ];
                            if (!empty($action['id'])) {
                                $postOptions['data'] = ['id' => $action['id']];
                            }
                            echo $this->Form->postLink($innerHtml, $url, $postOptions);
                        ?>
                    <?php else: ?>
                        <a class="<?= $fullBtnClass ?>"
                           href="<?= h($url) ?>"
                           <?= !empty($action['onclick']) ? 'onclick="' . $action['onclick'] . '"' : '' ?>>
                            <?= $innerHtml ?>
                        </a>
                    <?php endif; ?>

                <?php endforeach; ?>
            <?php else: ?>
                <p class="text-muted mb-0 small">No action available</p>
            <?php endif; ?>
        </div>
    </div>
</div>
