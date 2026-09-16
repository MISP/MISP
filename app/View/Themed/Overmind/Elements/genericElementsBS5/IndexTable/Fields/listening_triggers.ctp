<?php
$path = is_array($data_path) ? reset($data_path) : $data_path;
$triggers = Hash::get($row, $path ?: 'Workflow.listening_triggers');

if (empty($triggers) || !is_array($triggers)) {
    echo sprintf('<span class="text-muted small">%s</span>', __('none'));
    return;
}
xdebug_break();
?>
<div class="wf-scope d-flex flex-wrap gap-1">
    <?php foreach ($triggers as $trigger): ?>
        <?php
            $id = (string)($trigger['id'] ?? '');
            $disabled = !empty($trigger['disabled']);
            $isAdhoc = !empty($trigger['is_adhoc']) || strpos($id, 'adhoc_') === 0;
            $title = $disabled
                ? __('Trigger disabled')
                : ($isAdhoc ? __('Ad-hoc trigger — run manually') : ($trigger['name'] ?? $id));
            $ref = $isAdhoc ? h($baseurl) . '/workflows/adhoc/quickFilter:'. $row['Workflow']['name']: h($baseurl) . '/workflows/triggers/quickFilter:'. $trigger['name'];
        ?>
        <a class="wf-chip wf-chip-<?= $isAdhoc ? 'manual' : 'auto' ?> text-decoration-none<?= $disabled ? ' opacity-50 text-decoration-line-through' : '' ?>"
           href="<?= h($ref) ?>"
           title="<?= h($title) ?>">
            <i class="fa-fw <?= h($this->FontAwesome->getClass($trigger['icon'] ?? 'flag')) ?>"></i><?= h($id) ?>
        </a>
    <?php endforeach; ?>
</div>
