<?php
/*
 * The muted one-liner that sits under a field in a modal, explaining what the
 * value does or how it is parsed.
 *
 * Required params:
 *   $text   string  the hint
 *
 * Optional params:
 *   $icon   string  full class attribute of the leading glyph
 *                   (default 'fas fa-circle-info'; '' drops it)
 *   $class  string  spacing and any extra classes (default 'mt-1')
 *
 * A hint long enough to wrap centres its glyph against both lines, which is
 * how it has always looked; `align-items-start` plus a small top margin on the
 * glyph would fix that for every hint at once, from here.
 */

$icon = $icon ?? 'fas fa-circle-info';
?>
<div class="d-flex align-items-center gap-1 <?= h($class ?? 'mt-1') ?> text-muted"
     style="font-size:.75rem;">
    <?php if ($icon !== ''): ?><i class="<?= h($icon) ?>" style="font-size:.65rem;"></i><?php endif; ?>
    <?= h($text ?? '') ?>
</div>
