<?php
/*
 * Metric pill card for statistics rows.
 *
 * Expected variables:
 *   $icon  (string)      FA icon class e.g. 'fa-tag'
 *   $color (string)      Hex color for the icon & accent
 *   $label (string)      Human-readable label
 *   $value (int|null)    Current value; null shows a spinner
 *   $id    (string|null) DOM id prefix (optional)
 */
$bgAlpha = $color . '18';   /* ~10% opacity tint */
$id      = $id ?? null;
?>

<div class="rounded-3 p-3 h-100 d-flex align-items-center gap-3"
     style="background:<?= h($bgAlpha) ?>;border:1px solid <?= h($color) ?>22; cursor:<?= isset($onclick) ? 'pointer' : 'default' ?>;"
     onclick="<?= isset($onclick) ? h($onclick) : '' ?>">

    <!-- Icon circle -->
    <div class="rounded-circle d-flex align-items-center justify-content-center flex-shrink-0"
         style="width:40px;height:40px;background:<?= h($color) ?>22;">
        <i class="<?= h($icon) ?>" style="color:<?= h($color) ?>;font-size:1.1rem;"></i>
    </div>

    <!-- Value + label -->
    <div class="lh-1">
        <div class="fw-bold fs-5"
            <?= $id ? 'id="' . h($id) . '-value"' : '' ?>>
            <?php if ($value !== null): ?>
                <?= h($value) ?>
            <?php else: ?>
                <span class="spinner-border spinner-border-sm text-muted"
                      role="status" style="width:.9rem;height:.9rem;"></span>
            <?php endif; ?>
        </div>
        <div class="small text-muted mt-1"><?= h($label) ?></div>
    </div>

</div>
