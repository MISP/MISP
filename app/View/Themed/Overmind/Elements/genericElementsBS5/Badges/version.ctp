<?php
/*
 * Expected:
 * $version (int)
 * $full (bool) → Print label or just icon
 */

$version = isset($version) ? (int)$version : null;

?>


<span class="badge bg-primary-subtle text-primary-emphasis fw-semibold px-3 py-2">
    v<?= h($version) ?>
</span>