<?php
/*
 * Workflow module identity cell: tinted icon frame + name over description.
 *
 * Hues are named rather than spread by golden angle: there are only two, and one
 * of them should keep the violet the workflow hub already uses for "modules".
 * The palette still comes from GalaxyColour so every hsl() lives in one place.
 */
$MODULE_TYPE_HUE = [
    'action' => 258,  // violet — matches the hub's Modules accent (#8B5CF6)
    'logic'  => 322,  // magenta — far from violet, and from the trigger teal
                      // and ad-hoc amber used by the sibling indexes
];

$name        = Hash::get($row, 'name') ?? '';
$description = Hash::get($row, 'description') ?? '';
$icon        = Hash::get($row, 'icon') ?? '';
$iconPath    = Hash::get($row, 'icon_path') ?? '';
$type        = Hash::get($row, 'module_type') ?? '';

$palette = isset($MODULE_TYPE_HUE[$type])
    ? $this->GalaxyColour->paletteFromHue($MODULE_TYPE_HUE[$type])
    : $this->GalaxyColour->palette($type);
?>
<div class="d-flex align-items-center gap-2">
    <span class="d-inline-flex align-items-center justify-content-center rounded-3 shadow-sm flex-shrink-0"
          style="width:2.25rem;height:2.25rem;background:<?= $palette['tintBg'] ?>;color:<?= $palette['tintIcon'] ?>;"
          title="<?= h(__('Type: %s', $type)) ?>">
        <?php if (!empty($icon)): ?>
            <i class="<?= h($this->FontAwesome->getClass($icon)) ?>"></i>
        <?php elseif (!empty($iconPath)): ?>
            <?php // misp-modules ship an image rather than a Font Awesome name ?>
            <img src="<?= h($baseurl . '/img/' . $iconPath) ?>"
                 alt="<?= h(__('Icon of %s', $name)) ?>"
                 style="width:1rem;height:1rem;object-fit:contain;">
        <?php else: ?>
            <i class="fas fa-cube"></i>
        <?php endif; ?>
    </span>
    <div class="d-flex flex-column overflow-hidden">
        <span class="fw-semibold"><?= h($name) ?></span>
        <?php if (!empty($description)): ?>
            <span class="text-muted small text-truncate" style="max-width:480px;" title="<?= h($description) ?>"><?= h($description) ?></span>
        <?php endif; ?>
    </div>
</div>
