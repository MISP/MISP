<?php
/**
 * @var string $icon A Font Awesome name, without the `fa-`
 * @var string $title
 * @var array|null $status `text` and `tone` (a pill class)
 */
?>
<header class="ap-card-head">
    <span class="ap-card-icon" aria-hidden="true"><i class="fas fa-<?= h($icon) ?>"></i></span>
    <h2 class="ap-card-title"><?= h($title) ?></h2>
    <?php if (!empty($status)): ?>
        <span class="pill <?= h($status['tone']) ?>"><?= h($status['text']) ?></span>
    <?php endif; ?>
</header>
