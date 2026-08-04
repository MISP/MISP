<div>
    <?php if (!empty($item['image'])): ?> 
        <?= $item['image'] ?>
    <?php elseif (!empty($item['icon'])): ?>
        <i class="<?= h($item['icon']) ?> fa-fw"></i>
    <?php endif; ?>
    <span><?= h($item['label']) ?></span>
</div>