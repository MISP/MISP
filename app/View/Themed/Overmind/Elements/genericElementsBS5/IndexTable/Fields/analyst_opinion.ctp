<?php
/*
 * Renders the opinion as a coloured score badge with its comment underneath.
 *
 * Config:
 *   $field['model'] — model key holding 'opinion' and 'comment' (e.g. 'Opinion')
 */
$m = $field['model'] ?? 'Opinion';
$o = (int)($row[$m]['opinion'] ?? 0);
$o = max(0, min(100, $o));
$comment = (string)($row[$m]['comment'] ?? '');

$label = $o >= 81 ? __('Strongly Agree')
    : ($o >= 61 ? __('Agree')
    : ($o >= 41 ? __('Neutral')
    : ($o >= 21 ? __('Disagree') : __('Strongly Disagree'))));
$color = $o === 50 ? 'secondary' : ($o > 50 ? 'success' : 'danger');
?>
<div class="d-flex flex-column gap-1">
    <span class="badge bg-<?= $color ?>-subtle text-<?= $color ?>-emphasis border border-<?= $color ?>-subtle fw-semibold align-self-start">
        <?= h($label) ?> &middot; <?= $o ?>/100
    </span>
    <?php if ($comment !== ''): ?>
        <span class="text-muted small idx-col-wrap"><?= nl2br(h($comment)) ?></span>
    <?php endif; ?>
</div>
