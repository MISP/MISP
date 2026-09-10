<?php
/*
 * An ordered choice as a slider: the same options `choice_cards` takes, drawn
 * as the filled meter the event view shows for the very same value.
 * Use it where the values are a scale — analysis level, threat level — and cards where they are not
 * (distribution: a sharing group is not "more" than all communities).
 *
 * `$options` are in scale order, lowest first: the slider's position is the
 * index, never the posted value. A hidden <select> holds the value, so the
 * field posts and is covered by the Security token exactly like a select.
 *
 * Required params:
 *   $field    string  form field name, e.g. 'threat_level_id'
 *   $options  array   the stops, lowest first; per stop:
 *                       value  scalar  the posted value              (required)
 *                       title  string  the stop's name                (required)
 *                       sub    string  one line on what the stop means
 *                       tone   string  its colour — fills the track and paints
 *                                      the readout (default: the accent)
 *
 * Optional params:
 *   $value       mixed   the selected value — the request's own value for the
 *                        field still wins (default: the first stop's)
 *   $accent      string  accent key, see ModalAccent (default 'primary')
 *   $id          string  id of the hidden select; Cake's own when omitted
 *   $ariaLabel   string  what the slider is choosing, for screen readers
 *   $class       string  extra classes on the wrapper
 *   $selectAttrs array   extra attributes for the hidden select
 *   $reveal      array   ['value' => x, 'target' => '#id'] — toggles `d-none`
 *                        on the target as that one value is picked or left
 */

$accentMeta = $this->ModalAccent->get($accent ?? 'primary');
$options = array_values($options ?? []);
$last = count($options) - 1;

/* Same precedence as choice_cards: the request first (an edit, or a form back
 * from a failed validation), then the caller, then the bottom of the scale. */
$posted = $this->Form->value($field);
if ($posted !== null && $posted !== '') {
    $selected = (string)$posted;
} elseif (isset($value) && $value !== '') {
    $selected = (string)$value;
} else {
    $selected = isset($options[0]) ? (string)$options[0]['value'] : '';
}

$index = 0;
foreach ($options as $i => $option) {
    if ((string)$option['value'] === $selected) {
        $index = $i;
        break;
    }
}
$current = $options[$index] ?? ['title' => '', 'sub' => '', 'tone' => ''];
$tone = !empty($current['tone'])
    ? $current['tone']
    : $accentMeta['colour'];

$selectOptions = [];
foreach ($options as $option) {
    $selectOptions[$option['value']] = $option['title'];
}

$selectAttrs = $selectAttrs ?? [];
$selectAttrs['value'] = $selected;
$selectAttrs['class'] = trim(($selectAttrs['class'] ?? '') . ' d-none');
$selectAttrs['data-choice-input'] = 'true';
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

/* The whole initial state is rendered here rather than painted by the JS on
 * load, so the field never shows a wrong stop for a frame. */
$style = sprintf(
    '--ov-slider-accent:%s; --ov-slider-tone:%s; --ov-slider-fill:%s%%;',
    $accentMeta['colour'],
    $tone,
    $last > 0 ? round($index / $last * 100) : 0
);
?>
<div class="ov-slider <?= h($class ?? '') ?>"
     data-choice-slider
     style="<?= $style ?>"<?= $revealAttrs ?>>

    <?= $this->Form->select($field, $selectOptions, $selectAttrs) ?>

    <div class="ov-slider-head">
        <span class="ov-slider-value" data-slider-value>
            <?= h($current['title']) ?>
        </span>
        <span class="ov-slider-sub" data-slider-sub>
            <?= h($current['sub'] ?? '') ?>
        </span>
    </div>

    <input type="range"
           class="ov-slider-range"
           data-choice-slider-input
           min="0"
           max="<?= (int)max($last, 0) ?>"
           step="1"
           value="<?= (int)$index ?>"
           <?= empty($ariaLabel) ? '' : 'aria-label="' . h($ariaLabel) . '"' ?>
           aria-valuetext="<?= h($current['title']) ?>">

    <div class="ov-slider-ticks">
        <?php foreach ($options as $i => $option): ?>
        <span class="ov-slider-tick<?= $i === $index ? ' is-current' : '' ?>"
              data-slider-index="<?= (int)$i ?>"
              data-sub="<?= h($option['sub'] ?? '') ?>"
              <?php if (!empty($option['tone'])): ?>
              style="--ov-slider-tone:<?= h($option['tone']) ?>"
              <?php endif; ?>><?= h($option['title']) ?></span>
        <?php endforeach; ?>
    </div>
</div>
