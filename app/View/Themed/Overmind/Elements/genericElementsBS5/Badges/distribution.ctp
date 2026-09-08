<?php

/*
 * Expected:
 * $distribution (int)
 * $full (bool) → Print label or just icon
 */

$distribution = isset($distribution) ? (int)$distribution : null;
$full = $full ?? true;

// Canonical presentation for the level, unknown-level entry included.
$config = $this->DistributionLevel->get($distribution);

?>

<span class="badge d-inline-flex align-items-center px-2 py-1"
      style="
        background-color: <?= h($config['bg']) ?>;
        color: <?= h($config['color']) ?>;
        border: 1px solid <?= h($config['color']) ?>20;
        font-weight: 500;
      "
      title="<?= h($config['label']) ?>">

    <i class="<?= h($config['icon']) ?>"></i>

    <?php if ($full): ?>
        <span class="ms-1">
            <?= h($config['label']) ?>
        </span>
    <?php endif; ?>

</span>