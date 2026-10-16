<?php
/**
 * Where the number is, and what kind of line.
 *
 * The carrier and line type are the two fields the missing module
 * would fill, and they are drawn as blanks rather than omitted: an
 * analyst who ranked this shape asked for them, and a widget silently
 * without them looks like an answer rather than like a gap.
 *
 * @var array $data
 */
$number = $data['headline'];
?>
<div class="vp-rw-in vp-rw-phone">
    <?php if ($number['country'] !== null): ?>
        <div class="vp-rw-head"><?= h($number['country']) ?></div>
    <?php elseif ($number['brand'] !== null): ?>
        <div class="vp-rw-head"><?= h($number['brand']) ?></div>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('number')) ?></div>
    <?php endif; ?>
    <?php if ($number['carrier'] !== null): ?>
        <div class="vp-rw-sub"><?= h($number['carrier']) ?></div>
    <?php endif; ?>
    <?php if ($number['line_type'] !== null): ?>
        <div class="vp-rw-note"><?= h($number['line_type']) ?></div>
    <?php endif; ?>
    <?php if ($number['model'] !== null): ?>
        <div class="vp-rw-note"><?= h($number['model']) ?></div>
    <?php endif; ?>
    <?php if ($number['number'] !== null): ?>
        <div class="vp-rw-note font-monospace"><?=
            h($number['number']) ?></div>
    <?php endif; ?>
</div>
