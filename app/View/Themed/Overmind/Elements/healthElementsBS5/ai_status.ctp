<?php
/**
 * Status card of the AI settings tab: the ai_connector module as seen from
 * this instance, computed by Module::aiStatus() when the tab loads.
 *
 * Params:
 *  - status  array from Module::aiStatus()
 */

$pill = function ($level, $label, $icon = null) {
    $icons = array(0 => 'circle-xmark', 1 => 'triangle-exclamation', 2 => 'circle-check', 3 => 'circle-info');
    return sprintf(
        '<span class="ss-prio ss-lvl-%d"><i class="fas fa-%s"></i>%s</span>',
        (int)$level,
        h($icon ?: $icons[$level]),
        h($label)
    );
};
$row = function ($label, $right) {
    printf(
        '<div class="dg-row"><span class="dg-row-label">%s</span><span class="ms-auto d-flex align-items-center gap-2 flex-wrap justify-content-end">%s</span></div>',
        h($label),
        $right
    );
};

if (!$status['enabled']) {
    $verdict = array('level' => 3, 'label' => __('Disabled'), 'accent' => '#6c757d');
} elseif (!$status['reachable']) {
    $verdict = array('level' => 0, 'label' => __('Unreachable'), 'accent' => '#dc3545');
} elseif (!$status['listed']) {
    $verdict = array('level' => 1, 'label' => __('Module missing'), 'accent' => '#fd7e14');
} else {
    $verdict = array('level' => 2, 'label' => __('Ready'), 'accent' => '#198754');
}
?>
<div class="card shadow-sm mb-3 ss-section dg-card" id="ai-status-card" style="--ss-accent: <?= h($verdict['accent']) ?>;">
    <div class="card-header ss-section-header" style="cursor:default;">
        <span class="ss-section-icon"><i class="fas fa-robot"></i></span>
        <div class="flex-grow-1">
            <div class="fw-semibold"><?= __('Module status') ?></div>
            <div class="text-muted" style="font-size:.78rem;"><?= __('The ai_connector module as seen from this instance, checked when this tab loads') ?></div>
        </div>
        <?= $pill($verdict['level'], $verdict['label']) ?>
    </div>
    <div class="card-body">
        <?php
        $row(__('AI services'), $status['enabled']
            ? $pill(2, __('Enabled'))
            : $pill(3, __('Disabled')) . '<span class="text-muted small">' . __('Set %s to true to check the module.', '<code>Plugin.AI_services_enable</code>') . '</span>');
        $row(__('Module server'), '<code>' . h($status['server']) . '</code>');
        if ($status['enabled']) {
            $row(__('Reachable'), $status['reachable']
                ? $pill(2, __('Yes'))
                : $pill(0, __('No')) . '<span class="text-danger small">' . h($status['error']) . '</span>');
        }
        if ($status['reachable']) {
            if ($status['listed']) {
                $module = $status['module'];
                $details = array();
                if (!empty($module['version'])) {
                    $details[] = __('version %s', h($module['version']));
                }
                if (!empty($module['description'])) {
                    $details[] = h($module['description']);
                }
                $row(__('ai_connector'), $pill(2, __('Listed')) . ($details ? '<span class="text-muted small">' . implode(' — ', $details) . '</span>' : ''));
            } else {
                $row(__('ai_connector'), $pill(1, __('Not listed'))
                    . '<span class="text-muted small">' . ($status['error'] ? h($status['error']) : __('The server answers, but does not offer the ai_connector module.')) . '</span>');
            }
        }
        ?>
    </div>
</div>
