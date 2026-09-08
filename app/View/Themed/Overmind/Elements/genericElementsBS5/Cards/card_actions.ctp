<?php
/**
 * The quick-action card of a detail view: one full-width button per action.
 *
 * An entry is an action, or a separator when it carries 'divider' — which is
 * how a long list (the event view has ~16 entries) is broken into groups
 * without every call site having to draw its own rule.
 *
 * Action params :
 * - 'url' => string,
 * - 'icon' => string,
 * - 'label' => string,
 * - 'success' => bool (optional),
 * - 'warning' => bool (optional),
 * - 'danger' => bool (optional),
 * - 'onclick' => string (optional)
 * - 'tour' => string (optional) — emits data-tour, an anchor for the
 *   onboarding tour to spotlight this specific action.
 * - 'type' => 'post' (optional) — renders a postLink, with 'confirm' and 'id'
 *
 * Separator params :
 * - 'divider' => true          a hairline between two groups
 * - 'label' => string          turns it into a group heading (optional)
 */

$actions = $actions ?? [];

/* A group heading, or a bare rule when it has no label. */
$renderDivider = function (array $spec) {
    if (empty($spec['label'])) {
        return '<hr class="my-1 opacity-25">';
    }

    return sprintf(
        '<div class="d-flex align-items-center gap-2 mt-2">'
            . '<span class="text-uppercase fw-semibold text-body-secondary flex-shrink-0"'
            . ' style="font-size:.72rem; letter-spacing:.1em;">%s</span>'
            . '<span class="flex-grow-1 border-top"></span>'
        . '</div>',
        h($spec['label'])
    );
};
?>


<div class="card shadow-sm mb-3" data-tour="quick-actions">

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
                    if (!empty($action['divider'])) {
                        echo $renderDivider($action);
                        continue;
                    }
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

                    $fullBtnClass = "quick-action btn $btnClass d-flex align-items-center justify-content-between rounded-4 p-3 w-100 border-0";
                    $btnStyle = 'font-size:.9rem;';
                ?>
                    <?php if (isset($action['type']) && $action['type'] === 'post'): ?>
                        <?php
                            $postOptions = [
                                'escape' => false,
                                'class' => $fullBtnClass,
                                'style' => $btnStyle,
                                'confirm' => $action['confirm'] ?? null,
                            ];
                            if (!empty($action['id'])) {
                                $postOptions['data'] = ['id' => $action['id']];
                            }
                            if (!empty($action['tour'])) {
                                $postOptions['data-tour'] = $action['tour'];
                            }
                            echo $this->Form->postLink($innerHtml, $url, $postOptions);
                        ?>
                    <?php else: ?>
                        <a class="<?= $fullBtnClass ?>"
                           style="<?= $btnStyle ?>"
                           href="<?= h($url) ?>"
                           <?= !empty($action['tour']) ? 'data-tour="' . h($action['tour']) . '"' : '' ?>
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
