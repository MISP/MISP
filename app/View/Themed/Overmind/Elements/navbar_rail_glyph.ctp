<?php if (!empty($item['image'])): ?>
    <span class="rail-avatar" aria-hidden="true"><?= $item['image'] ?></span>
<?php else: ?>
    <span class="rail-ico" aria-hidden="true"><?php if (!empty($item['icon'])): ?><i class="<?= h($item['icon']) ?> fa-fw<?= !empty($extraClass) ? ' ' . h($extraClass) : '' ?>"></i><?php else: ?><span class="rail-pip"></span><?php endif; ?></span>
<?php endif; ?>
