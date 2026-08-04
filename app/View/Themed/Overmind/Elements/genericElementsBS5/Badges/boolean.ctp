<?php
/*
 * Expected:
 * $boolean (bool)
 * $full (bool)        → Print label or just icon
 * $true (string)      → Label if boolean is true
 * $false (string)     → Label if boolean is false
 * $trueColor (string) → Color if true
 * $falseColor (string)→ Color if false
 * $trueIcon (string)  → Icon if true
 * $falseIcon (string) → Icon if false
 */
$boolean    = $boolean    ?? false;
$full       = $full       ?? true;
$true       = $true       ?? null;
$false      = $false      ?? null;
$trueColor  = $trueColor  ?? null;
$falseColor = $falseColor ?? null;
$trueIcon   = $trueIcon   ?? null;
$falseIcon  = $falseIcon  ?? null;

$color  = $boolean ? $trueColor  : $falseColor;
$icon   = $boolean ? $trueIcon   : $falseIcon;
$label  = $boolean ? $true       : $false;
?>
<div class="d-flex align-items-center">
        <?php if (($full) && !empty($true)): ?>
        <!-- CARD MODE -->
        <span class="badge d-inline-flex align-items-center px-2 py-1 border border-<?= $color ?> text-<?= $color ?>">
            <i class="fas <?= $icon ?> text-<?= $color ?> me-1"></i>
            <?= $label ?>
        </span>
    <?php elseif(!$full): ?>
        <!-- TABLE MODE -->
        <i class="fas
            <?= $boolean ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?>"
            style="font-size: 1.3em;"
            title="<?= $label ?>"
            aria-label="<?= $label ?>">
        </i>
    <?php endif; ?>
</div>