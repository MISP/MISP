<div id="<?= h($workflowPart['id']) ?>" class="sidebar-workflow-parts" style="user-select: none;" data-partid="<?= h($workflowPart['id']) ?>" title="<?= h($workflowPart['description']) ?>">
    <div>
        <div style="display: flex;">
            <strong class="name">
                <?= h($workflowPart['name']) ?>
            </strong>
            <span class="timestamp">v<?= h($workflowPart['timestamp']) ?></span>
        </div>
        <div><small class="muted"><?= h($workflowPart['uuid']) ?></small></div>
        <div><?= __n('Content: %s part', 'Content: %s nodes', count($workflowPart['data']), count($workflowPart['data'])) ?></div>
        <div class="muted"><?= h($workflowPart['description']) ?></div>
    </div>
</div>