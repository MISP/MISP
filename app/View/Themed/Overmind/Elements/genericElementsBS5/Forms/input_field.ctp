<?php
/*
 * A field drawn in the date field's box (Forms/date_field): a border, a leading
 * glyph and a focus ring in the modal's accent. One box for a text, a textarea
 * and a select, so the fields of a form read as one set. The look is
 * `.ov-form-field` in mainOvermind.css (FORM FIELDS); a rejected field takes
 * `is-invalid-field` and an `.ov-field-error` under it, as the event form's do.
 *
 * A select stays a plain <select> until the host script makes it a TomSelect;
 * the box then holds TomSelect's wrapper, and draws the chevron itself.
 *
 * Required params:
 *   $field        string  form field name, e.g. 'comment'
 *
 * Optional params:
 *   $type         string  'text' (default), 'textarea' or 'select'
 *   $id           string  id of the control; Cake's own when omitted
 *   $accent       string  accent key, see ModalAccent (default 'primary')
 *   $icon         string  full class attribute of the leading glyph, none when empty
 *   $mono         bool    monospaced text, for values and hashes
 *   $placeholder  string
 *   $rows         int     textarea rows (default 3)
 *   $options      array   select options
 *   $empty        string  select empty option, which TomSelect shows as its
 *                         placeholder (default: none)
 *   $value        mixed   the value; the request's own still wins, as Cake does
 *   $locked       bool    disabled, with a lock where the chevron was
 *   $lockedTitle  string  why it is locked, as the box's tooltip
 *   $footHtml     string  raw HTML of a strip under a textarea — escape it yourself
 *   $inputAttrs   array   merged into the control's options (data-*, …)
 *   $class        string  extra classes on the box
 */
$type = in_array($type ?? 'text', ['text', 'textarea', 'select'], true) ? ($type ?? 'text') : 'text';
$accentMeta = $this->ModalAccent->get($accent ?? 'primary');
$locked = !empty($locked);
$hasIcon = !empty($icon);

$controlClass = trim('ov-form-bare' . (!empty($mono) ? ' ov-form-mono' : ''));
$attrs = array_merge(array_filter([
    'id' => $id ?? null,
    'placeholder' => $placeholder ?? null,
    'disabled' => $locked ?: null,
    'data-locked' => $locked ? '1' : null,
], function ($v) {
    return $v !== null;
}), $inputAttrs ?? []);
if (isset($value)) {
    $attrs['value'] = $value;
}

$boxClasses = ['ov-form-field'];
if ($type === 'select') {
    $boxClasses[] = 'is-select';
}
if ($type === 'textarea') {
    $boxClasses[] = 'is-area';
}
if ($hasIcon) {
    $boxClasses[] = 'has-glyph';
}
if ($locked) {
    $boxClasses[] = 'is-locked';
}
if (!empty($class)) {
    $boxClasses[] = $class;
}
$glyph = $hasIcon ? '<i class="' . h($icon) . ' ov-form-glyph" aria-hidden="true"></i>' : '';
?>
<div class="<?= h(implode(' ', $boxClasses)) ?>"
     style="--ov-form-accent:<?= h($accentMeta['colour']) ?>;"<?= $locked && !empty($lockedTitle) ? ' title="' . h($lockedTitle) . '"' : '' ?>>
<?php if ($type === 'select'): ?>
    <?= $glyph ?>
    <?= $this->Form->select($field, $options ?? [], array_merge($attrs, [
        'class' => 'ov-form-select',
        'empty' => $empty ?? false,
    ])) ?>
    <i class="fas fa-<?= $locked ? 'lock' : 'chevron-down' ?> ov-form-chev" aria-hidden="true"></i>
<?php elseif ($type === 'textarea'): ?>
    <div class="ov-form-row">
        <?= $glyph ?>
        <?= $this->Form->textarea($field, array_merge($attrs, [
            'class' => $controlClass,
            'rows' => $rows ?? 3,
        ])) ?>
    </div>
    <?php if (!empty($footHtml)): ?>
        <div class="ov-form-foot"><?= $footHtml ?></div>
    <?php endif; ?>
<?php else: ?>
    <?= $glyph ?>
    <?= $this->Form->text($field, array_merge($attrs, ['class' => $controlClass])) ?>
<?php endif; ?>
</div>
