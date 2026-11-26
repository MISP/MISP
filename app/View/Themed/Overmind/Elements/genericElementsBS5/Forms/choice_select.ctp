<?php
/*
 * The compact shape of a choice: one TomSelect where every option — and the
 * picked one, in the closed control — wears its glyph in a tinted badge.
 *
 * Same contract as choice_cards.ctp — the same $options, the same $reveal — so
 * a form swaps one element name for the other when a field has to shrink to a
 * single line (an attribute's distribution beside its value, where five tiles
 * would outweigh everything around them).
 *
 * Unlike the cards, the <select> here IS the control rather than a hidden
 * mirror of it: there is nothing to keep in sync, only the glyph to swap.
 *
 * Required params:
 *   $field    string  form field name, e.g. 'distribution'
 *   $options  array   the choices, in display order; per choice:
 *                       value   scalar  the posted value              (required)
 *                       title   string  the option's wording          (required)
 *                       icon    string  full class attribute of a glyph
 *                       dot     string  colour of a dot, for an option with no
 *                                       glyph — ignored when `icon` is set
 *                       tone    string  glyph / dot colour (default: the accent)
 *                     `sub` is accepted and ignored: an <option> is one line.
 *
 * Optional params:
 *   $value       mixed   the selected value — the request's own value for the
 *                        field still wins (default: the first option's)
 *   $accent      string  accent key, see ModalAccent (default 'primary')
 *   $id          string  id of the select; Cake's own when omitted
 *   $ariaLabel   string  what the field is choosing, for screen readers
 *   $class       string  extra classes on the wrapper
 *   $selectAttrs array   extra attributes for the select — a class of its own,
 *                        or the data-* hook a host form listens on
 *   $reveal      array   ['value' => 4, 'target' => '#sg'] — toggles `d-none`
 *                        on the target as that one value is picked or left
 */

$accentMeta = $this->ModalAccent->get($accent ?? 'primary');
$options = array_values($options ?? []);

/* Cake's own precedence, the same one choice_cards applies: what the request
 * holds — an edit, or a form coming back from a failed validation — outranks
 * the caller's value, and only then the first option. */
$posted = $this->Form->value($field);
if ($posted !== null && $posted !== '') {
    $selected = (string)$posted;
} elseif (isset($value) && $value !== '') {
    $selected = (string)$value;
} else {
    $selected = isset($options[0]) ? (string)$options[0]['value'] : '';
}

$selectOptions = [];
foreach ($options as $option) {
    $selectOptions[$option['value']] = $option['title'];
}

$selectAttrs = $selectAttrs ?? [];
$selectAttrs['value'] = $selected;
$selectAttrs['class'] = trim(
    'form-select ov-choice-select-input ' . ($selectAttrs['class'] ?? '')
);
$selectAttrs['data-choice-input'] = 'true';
$selectAttrs['empty'] = false;
if (!empty($id)) {
    $selectAttrs['id'] = $id;
}
if (!empty($ariaLabel)) {
    $selectAttrs['aria-label'] = $ariaLabel;
}

$revealAttrs = '';
if (!empty($reveal['target'])) {
    $revealAttrs = sprintf(
        ' data-choice-reveal-value="%s" data-choice-reveal-target="%s"',
        h((string)$reveal['value']),
        h($reveal['target'])
    );
}

/* The glyphs are handed to JavaScript as data rather than as markup: TomSelect
 * builds both the closed control and every row of the dropdown itself, so what
 * it needs is the table, not a pre-rendered icon. */
$meta = [];
foreach ($options as $option) {
    if (empty($option['icon']) && empty($option['dot'])) {
        continue;
    }
    $meta[] = [
        'value' => (string)$option['value'],
        'icon' => $option['icon'] ?? '',
        'tone' => $option['tone'] ?? $option['dot'] ?? '',
        'toneBg' => $option['toneBg'] ?? '',
    ];
}
?>
<div class="ov-choice-select <?= h($class ?? '') ?>"
     data-choice-select
     style="--ov-choice-accent: <?= $accentMeta['colour'] ?>;"
     <?= $revealAttrs ?>>

    <?php foreach ($meta as $entry): ?>
        <span class="d-none"
              data-choice-icon="<?= h($entry['value']) ?>"
              data-icon="<?= h($entry['icon']) ?>"
              data-tone="<?= h($entry['tone']) ?>"
              data-tone-bg="<?= h($entry['toneBg']) ?>"></span>
    <?php endforeach; ?>

    <?= $this->Form->select($field, $selectOptions, $selectAttrs) ?>
</div>
