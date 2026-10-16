<?php if (!empty($item['image'])): ?>
    <span class="rc-avatar" aria-hidden="true"><?= $item['image'] ?></span>
<?php else: ?>
    <span class="rc-ico" aria-hidden="true"><?php if (!empty($item['icon'])): ?><i class="<?= h($item['icon']) ?> fa-fw<?= !empty($extraClass) ? ' ' . h($extraClass) : '' ?>"></i><?php endif; ?></span>
<?php endif; ?>
