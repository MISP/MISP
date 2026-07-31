<?php

$name        = Hash::get($row, 'name') ?? '';
$description = Hash::get($row, 'description') ?? '';
$icon        = Hash::get($row, 'icon') ?? '';
$scope       = Hash::get($row, 'scope') ?? '';

$palette = $this->GalaxyColour->paletteFromList($scope, $field['scopes'] ?? []);

$faClass = !empty($icon) ? h($this->FontAwesome->getClass($icon)) : 'fas fa-flag';
?>
<div class="d-flex align-items-center gap-2">
    <span class="d-inline-flex align-items-center justify-content-center rounded-3 shadow-sm flex-shrink-0"
          style="width:2.25rem;height:2.25rem;background:<?= $palette['tintBg'] ?>;color:<?= $palette['tintIcon'] ?>;"
          title="<?= h(__('Scope: %s', $scope)) ?>">
        <i class="<?= $faClass ?>"></i>
    </span>
    <div class="d-flex flex-column overflow-hidden">
        <span class="fw-semibold"><?= h($name) ?></span>
        <?php if (!empty($description)): ?>
            <span class="text-muted small text-truncate" style="max-width:480px;" title="<?= h($description) ?>"><?= h($description) ?></span>
        <?php endif; ?>
    </div>
</div>
