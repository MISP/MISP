<?php
/*
 * A radio group drawn as cards: one clickable tile per option, backed by a
 * hidden <select> so the value travels with the form — and with the Security
 * component's token — exactly as a plain select would.
 *
 * Required params:
 *   $field    string  form field name, e.g. 'analysis' or 'Object.distribution'
 *   $options  array   the cards, in display order; per card:
 *                       value   scalar  the posted value              (required)
 *                       title   string  the card's headline           (required)
 *                       sub     string  one-line qualifier under the title
 *                       icon    string  full class attribute of a glyph, drawn
 *                                       in a tinted tile
 *                       dot     string  colour of a dot, for a card with no
 *                                       glyph — ignored when `icon` is set
 *                       tone    string  glyph / dot colour (default: the accent)
 *                       toneBg  string  glyph-tile background (default: a 12%
 *                                       wash of the tone)
 *
 * Optional params:
 *   $value       mixed   the selected value — the request's own value for
 *                        the field still wins (default: the first option's)
 *   $accent      string  accent key, see ModalAccent (default 'primary')
 *   $id          string  id of the hidden select; Cake's own when omitted
 *   $columns     int     cards per row from lg up, 1-6 (default: as many as
 *                       there are options, capped at 6)
 *   $ariaLabel   string  what the group is choosing, for screen readers
 *   $class       string  extra classes on the wrapper
 *   $selectAttrs array   extra attributes for the hidden select — a class of
 *                        its own, or the data-* hook a host form listens on
 *   $reveal      array   ['value' => 4, 'target' => '#sg'] — toggles `d-none`
 *                        on the target as that one value is picked or left
 *
 * initChoiceCards() in mispOvermind.js does the wiring, and it runs on every
 * modal body and once on page load: a host form has nothing to call.
 */

$accentMeta = $this->ModalAccent->get($accent ?? 'primary');
$options = array_values($options ?? []);
$posted = $this->Form->value($field);
if ($posted !== null && $posted !== '') {
    $selected = (string)$posted;
} elseif (isset($value) && $value !== '') {
    $selected = (string)$value;
} else {
    $selected = isset($options[0]) ? (string)$options[0]['value'] : '';
}

$columns = (int)($columns ?? min(count($options), 6));
$columns = max(1, min(6, $columns));

/* The select carries the labels rather than the whole card: it is what a
 * screen reader without JS, and every host form's JS, reads the value from. */
$selectOptions = [];
foreach ($options as $option) {
    $selectOptions[$option['value']] = $option['title'];
}

$selectAttrs = $selectAttrs ?? [];
$selectAttrs['value'] = $selected;
$selectAttrs['class'] = trim(($selectAttrs['class'] ?? '') . ' d-none');
$selectAttrs['data-choice-input'] = 'true';
/* No empty option: the select must carry exactly the values the cards offer,
 * or a click could leave it on a value nothing is drawn for. */
$selectAttrs['empty'] = false;
if (!empty($id)) {
    $selectAttrs['id'] = $id;
}

$revealAttrs = '';
if (!empty($reveal['target'])) {
    $revealAttrs = sprintf(
        ' data-choice-reveal-value="%s" data-choice-reveal-target="%s"',
        h((string)$reveal['value']),
        h($reveal['target'])
    );
}
?>
<div class="ov-choice-group <?= h($class ?? '') ?>"
     data-choice-cards
     style="--ov-choice-accent: <?= $accentMeta['colour'] ?>;"
     <?= $revealAttrs ?>>

    <?= $this->Form->select($field, $selectOptions, $selectAttrs) ?>

    <div class="row g-2 row-cols-2 row-cols-md-3 row-cols-lg-<?= $columns ?>"
         role="radiogroup"
         <?= empty($ariaLabel) ? '' : 'aria-label="' . h($ariaLabel) . '"' ?>>
        <?php foreach ($options as $option):
            $optionValue = (string)$option['value'];
            $isSelected = $optionValue === $selected;
            $toneStyle = '';
            $tone = [];
            if (!empty($option['tone'])) {
                $tone[] = '--ov-choice-tone:' . $option['tone'];
            } elseif (!empty($option['dot'])) {
                $tone[] = '--ov-choice-tone:' . $option['dot'];
            }
            if (!empty($option['toneBg'])) {
                $tone[] = '--ov-choice-tone-bg:' . $option['toneBg'];
            }
            if (!empty($tone)) {
                $toneStyle = ' style="' . h(implode(';', $tone)) . '"';
            }
        ?>
        <div class="col">
            <div class="ov-choice<?= $isSelected ? ' is-selected' : '' ?>"
                 role="radio"
                 aria-checked="<?= $isSelected ? 'true' : 'false' ?>"
                 tabindex="<?= $isSelected ? '0' : '-1' ?>"
                 data-choice-value="<?= h($optionValue) ?>"<?= $toneStyle ?>>
                <?php if (!empty($option['icon'])): ?>
                    <span class="ov-choice-icon">
                        <i class="<?= h($option['icon']) ?>"></i>
                    </span>
                <?php elseif (!empty($option['dot'])): ?>
                    <span class="ov-choice-dot"></span>
                <?php endif; ?>
                <span class="ov-choice-title"><?= h($option['title']) ?></span>
                <?php if (!empty($option['sub'])): ?>
                    <span class="ov-choice-sub"><?= h($option['sub']) ?></span>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</div>
