<?php
/*
 * What AnalystData/thread shows when a record has no analyst data; a host with
 * its own layout renders it directly.
 *
 * Params:
 *   $class : extra wrapper classes (a flex host passes flex-grow-1)
 */
$class = trim('d-flex flex-column align-items-center justify-content-center text-muted py-4 ' . ($class ?? ''));
?>
<div class="<?= h($class) ?>">
    <i class="fas fa-comment-dots fa-2x mb-2 opacity-50" aria-hidden="true"></i>
    <p class="mb-0 small fw-semibold"><?= __('No notes, opinions or relationships yet.') ?></p>
</div>
