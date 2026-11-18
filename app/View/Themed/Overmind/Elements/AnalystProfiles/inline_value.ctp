<?php
/**
 * A setting changed where it is read: its value is a button, and a
 * click opens its box in place with a tick and a cross. Enter or the
 * tick saves that one setting, Escape or the cross leaves it as it was
 * (analyst-profile-settings.js). The caller's element carries
 * `data-ap-set`, the setting's address.
 *
 * @var array $field
 * @var string|null $unit Said after the value, and after the box
 */
$unit = isset($unit) && $unit !== '' ? $unit : null;
$value = $field['value'] ?? null;
$effective = $value === null ? ($field['default'] ?? null) : $value;

// The value as a reader says it: a choice by its label, a number grouped.
$shown = (string)$effective;
$named = false;
if (($field['type'] ?? '') === 'select') {
    foreach ($field['options'] ?? array() as $option) {
        if (is_array($option) && (string)$option['value'] === (string)$effective) {
            $shown = $option['label'] ?? $option['value'];
            $named = true;
            break;
        }
    }
    /*
     * A choice nobody made yet opens on the one in force: a box with no
     * option selected falls to the first, and the cross would then have
     * nothing to go back to.
     */
    if ($value === null) {
        $field['value'] = $effective;
    }
} elseif (isset($field['read_as'])) {
    $shown = (string)$field['read_as'];
} elseif (is_numeric($effective) && abs($effective) >= 1000) {
    $shown = number_format((float)$effective, floor($effective) == $effective ? 0 : 2);
}
// A value that follows another setting says what it follows.
if ($value === null && isset($field['follows'], $field['resolved'])) {
    $shown = sprintf(__('%1$s · follows %2$s'), $field['resolved'], $field['follows']);
} elseif (!$named && ($effective === null || $shown === '')) {
    $shown = __('not set');
}
?>
<span class="ap-set-saved" aria-live="polite"><i class="fas fa-check" aria-hidden="true"></i><?=
    h(__('Saved')) ?></span>
<button type="button" class="ap-set-v" data-ap-set-edit
        aria-label="<?= h(sprintf(__('Change %1$s, now %2$s'), $field['label'] ?? '', $shown)) ?>">
    <?= h($shown) ?><?php if ($unit !== null): ?> <span class="ap-set-u"><?= h($unit) ?></span><?php endif; ?>
    <i class="fas fa-pen" aria-hidden="true"></i>
</button>
<span class="ap-set-in" hidden>
    <?= $this->element('AnalystProfiles/field', array('field' => $field, 'editable' => true)) ?>
    <?php if ($unit !== null): ?>
        <span class="wb-unit"><?= h($unit) ?></span>
    <?php endif; ?>
    <button type="button" class="btn btn-sm btn-success" data-ap-set-save
            aria-label="<?= h(__('Save')) ?>" title="<?= h(__('Save')) ?>">
        <i class="fas fa-check" aria-hidden="true"></i>
    </button>
    <button type="button" class="btn btn-sm btn-outline-secondary" data-ap-set-cancel
            aria-label="<?= h(__('Cancel')) ?>" title="<?= h(__('Cancel')) ?>">
        <i class="fas fa-xmark" aria-hidden="true"></i>
    </button>
</span>
