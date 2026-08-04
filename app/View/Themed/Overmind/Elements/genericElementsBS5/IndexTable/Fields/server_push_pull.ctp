<?php
$mode = $field['mode'] ?? null;
$server = $row['Server'] ?? [];
if (empty($mode) || empty($server)) {
    return;
}

if ($mode === 'pull') {
    $enabled = !empty($server[$mode]);
} else {
    $enabled = !empty($server[$mode]) &&
        !empty(Hash::get($row, 'RuleDescription.' . $mode));
}

$rules = Hash::get($row, 'RuleDescription.' . $mode);
$serverId = $server['id'];
$isCard = isset($viewMode) && $viewMode === 'card';
$stateLabel = $enabled ? __('Enabled') : __('Disabled');
?>
<div class="d-flex flex-column gap-1">
    <?php if ($isCard): ?>
        <span class="small <?= $enabled ? 'text-success' : 'text-secondary' ?>">
            <i class="fas <?= $enabled ? 'fa-check-circle' : 'fa-times-circle' ?> me-1"></i>
            <?= h($stateLabel) ?>
        </span>
    <?php else: ?>
        <i
            class="fas <?= $enabled ? 'fa-check text-success' : 'fa-times text-secondary' ?>"
            title="<?= h($stateLabel) ?>"
            aria-label="<?= h($stateLabel) ?>"
        ></i>
    <?php endif; ?>

    <?php if ($enabled && !empty($rules)): ?>
        <span
            class="small text-muted"
            data-toggle="popover"
            title="<?= __('Distribution List') ?>"
            data-content="<?= h($rules) ?>"
        >
            (<?= __('Rules') ?>)
        </span>
    <?php endif; ?>

    <?php if ($enabled): ?>
        <button
            type="button"
            class="btn btn-sm btn-outline-primary text-nowrap"
            title="<?= __('Test synchronisation rules') ?>"
            aria-label="<?= __('Test synchronisation rules') ?>"
            onclick="testSyncRule('<?= h($serverId) ?>', '<?= h($mode) ?>');"
        >
            <?= $mode === 'push' ? __('Test Push Rules') : __('Test Pull Rules') ?>
        </button>
        <span
            id="sync_rule_<?= h($mode) ?>_test_<?= h($serverId) ?>"
            class="server-action-result small"
        ></span>
    <?php endif; ?>
</div>
