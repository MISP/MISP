<?php
/*
 * Expected:
 * $type (string)
 * $full (bool) → Print label or just icon
 */

$type = isset($type) ? $type : null;
?>

<div class="d-flex align-items-center">
    <p class="om-type mb-0"><?= h($type) ?></p>
</div>