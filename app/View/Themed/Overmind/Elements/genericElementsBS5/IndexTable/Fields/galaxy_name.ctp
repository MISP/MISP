<?php
/*
 * Galaxy identity cell: tinted glyph tile + name, with the description below.
 *
*/
$name        = Hash::extract($row, 'Galaxy.name')[0] ?? '';
$description = Hash::extract($row, 'Galaxy.description')[0] ?? '';
$icon        = Hash::extract($row, 'Galaxy.icon')[0] ?? '';

$palette = $this->GalaxyColour->palette($name);
$faClass = !empty($icon) ? h($this->FontAwesome->getClass($icon)) : 'fas fa-shapes';
$isCard  = isset($viewMode) && $viewMode === 'card';
?>
<div class="d-flex gap-2 overflow-hidden" style="min-width:0;max-width:100%;">
    <span class="d-inline-flex align-items-center justify-content-center rounded-3 shadow-sm flex-shrink-0"
          style="width:2.25rem;height:2.25rem;background:<?= $palette['tintBg'] ?>;color:<?= $palette['tintIcon'] ?>;">
        <i class="<?= $faClass ?>"></i>
    </span>
    <div class="d-flex flex-column overflow-hidden" style="min-width:0;">
        <span class="fw-semibold<?= $isCard ? '' : ' text-truncate' ?>" title="<?= h($name) ?>"><?= h($name) ?></span>
        <?php if (!empty($description)): ?>
            <span class="text-muted small <?= $isCard ? 'idx-clamp-2' : 'text-truncate' ?>"
                  <?= $isCard ? '' : 'style="max-width:480px;"' ?>
                  title="<?= h($description) ?>"><?= h($description) ?></span>
        <?php endif; ?>
    </div>
</div>
