<div id="<?= h($block['id']) ?>" class="sidebar-workflow-block" style="user-select: none;">
    <div class="icon">
        <?php if (!empty($block['icon'])) : ?>
            <i class="<?= $this->FontAwesome->getClass($block['icon']) ?> fa-fw <?= $block['icon_class'] ?? '' ?>"></i>
        <?php endif; ?>
    </div>
    <div>
        <strong style="font-size: large;"><?= h($block['name']) ?></strong>
        <div class="muted"><?= h($block['description']) ?></div>
    </div>
</div>