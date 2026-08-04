<?php

/*
 * Expected:
 * $count (int)
 */

$count = isset($count) ? (int)$count : null;

if ($count === 0) {
    $badgeClass = 'bg-secondary';
} else {
    $badgeClass = 'bg-primary';
}
?>

<span class="badge <?= $badgeClass ?> rounded-pill px-3 py-2 shadow-sm">
    <i class="fas fa-layer-group me-1"></i>
    <?= h($count) ?>
</span>