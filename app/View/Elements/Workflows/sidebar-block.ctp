<?php
$classFromSeverity = [
    'info' => 'info',
    'warning' => 'warning',
    'error' => 'danger',
]
?>
<div id="<?= h($block['id']) ?>" class="sidebar-workflow-block" style="user-select: none;" data-blockid="<?= h($block['id']) ?>">
    <div class="icon">
        <?php if (!empty($block['icon'])) : ?>
            <i class="<?= $this->FontAwesome->getClass($block['icon']) ?> fa-fw <?= $block['icon_class'] ?? '' ?>"></i>
        <?php endif; ?>
    </div>
    <div>
        <div style="display: flex;">
            <strong style="font-size: large;"><?= h($block['name']) ?></strong>
            <span class="block-notification-container">
                <?php foreach (array_keys($classFromSeverity) as $severity) : ?>
                    <?php if (!empty($block['notifications'][$severity])) : ?>
                        <button class="btn btn-mini btn-<?= $classFromSeverity[$severity] ?>" type="button" title="<?= implode('&#013;', h(Hash::extract($block['notifications'][$severity], '{n}.text'))) ?>" onclick="showNotificationModalForSidebarModule(this)">
                            <?php if ($severity == 'danger') : ?>
                                <i class="fas fa-times-circle"></i>
                            <?php elseif ($severity == 'warning') : ?>
                                <i class="fas fa-exclamation-triangle"></i>
                            <?php else : ?>
                                <i class="fas fa-exclamation-circle"></i>
                            <?php endif; ?>
                            <strong>
                                <?= count($block['notifications'][$severity]) ?>
                            </strong>
                        </button>
                    <?php endif; ?>
                <?php endforeach; ?>
            </span>
        </div>
        <div class="muted"><?= h($block['description']) ?></div>
    </div>
</div>
