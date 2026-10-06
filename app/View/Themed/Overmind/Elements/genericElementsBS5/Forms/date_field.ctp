<?php
/*
 * A date, or a date and time, picked from a calendar popover or typed by hand.
 * Everything is UTC — what MISP stores — and the field says so.
 *
 * The user reads and types DD/MM/YYYY (plus HH:MM:SS in datetime mode); the
 * form posts ISO (YYYY-MM-DD, or YYYY-MM-DD HH:MM:SS) through a text input
 * hidden by a class. A text input, not Form->hidden(): the Security token seals
 * a hidden field's value, and this one is rewritten by the picker. A stored
 * value the user never touches posts back exactly as it came, microseconds and
 * offset included.
 *
 * `initDateFields()` in mispOvermind.js binds every one of them in each modal
 * body, each lazy tab fragment and once on page load; one capture-phase submit
 * listener refuses a form holding a date it cannot read, an empty required one
 * or one outside its range, so a host form validates nothing.
 *
 * Required params:
 *   $field        string  form field name, e.g. 'first_seen', 'Object.last_seen'
 *
 * Optional params:
 *   $mode         string  'date' (default) or 'datetime'
 *   $value        string  ISO value — the request's own value for the field
 *                         still wins, as with the choice fields
 *   $id           string  id of the posted input; Cake's own when omitted.
 *                         The visible input is "<id>Display", for a label's `for`
 *   $accent       string  accent key, see ModalAccent (default 'primary')
 *   $placeholder  string  default: the format the field reads
 *   $required     bool    refuse a submit while the field is empty
 *   $requiredMsg  string  what the refusal says
 *   $invalidMsg   string  what an unreadable date is told
 *   $min / $max   string  ISO bounds, inclusive
 *   $after        string  selector of another date field's posted input this
 *                         one may not precede (a last seen after its first seen)
 *   $before       string  the reverse
 *   $rangeMsg     string  what a date outside min/max/after/before is told
 *   $clearable    bool    show the clear button (default: when not required)
 *   $icon         string  leading glyph (default 'fas fa-calendar-days')
 *   $class        string  classes on the wrapper (default 'w-100')
 *   $inputAttrs   array   merged into the posted input (data-*, …)
 */

$mode = ($mode ?? 'date') === 'datetime' ? 'datetime' : 'date';
$accentMeta = $this->ModalAccent->get($accent ?? 'primary');
$required = !empty($required);
$clearable = isset($clearable) ? (bool)$clearable : !$required;

$posted = $this->Form->value($field);
if ($posted !== null && $posted !== '') {
    $current = (string)$posted;
} else {
    $current = isset($value) ? (string)$value : '';
}

$inputId = $id ?? $this->Form->domId($field);
$displayId = $inputId . 'Display';

$defaults = $mode === 'datetime'
    ? ['placeholder' => 'DD/MM/YYYY HH:MM:SS']
    : ['placeholder' => 'DD/MM/YYYY'];

$labels = [
    'open' => __('Open calendar'),
    'prev' => __('Previous'),
    'next' => __('Next'),
    'today' => $mode === 'datetime' ? __('Now') : __('Today'),
    'clear' => __('Clear'),
    'done' => __('Done'),
    'time' => __('Time (UTC)'),
    'invalid' => $invalidMsg ?? ($mode === 'datetime'
        ? __('Enter a date as DD/MM/YYYY, optionally followed by HH:MM:SS.')
        : __('Enter a date as DD/MM/YYYY.')),
    'required' => $requiredMsg ?? __('This field is required.'),
    'range' => $rangeMsg ?? __('This date is outside the allowed range.'),
];

$wrapAttrs = [
    'data-date-field' => '1',
    'data-date-mode' => $mode,
    'data-date-required' => $required ? '1' : null,
    'data-date-min' => $min ?? null,
    'data-date-max' => $max ?? null,
    'data-date-after' => $after ?? null,
    'data-date-before' => $before ?? null,
];
$wrapAttrHtml = '';
foreach ($wrapAttrs as $name => $attrValue) {
    if ($attrValue !== null && $attrValue !== '') {
        $wrapAttrHtml .= ' ' . $name . '="' . h($attrValue) . '"';
    }
}
?>
<div class="ov-date <?= h($class ?? 'w-100') ?>"<?= $wrapAttrHtml ?>
     data-date-labels='<?= h(json_encode($labels)) ?>'
     style="--ov-date-accent:<?= h($accentMeta['colour']) ?>;">
    <div class="ov-date-box" data-date-box>
        <i class="<?= h($icon ?? 'fas fa-calendar-days') ?> ov-date-glyph" aria-hidden="true"></i>
        <input type="text"
               id="<?= h($displayId) ?>"
               class="ov-date-input"
               data-date-display
               inputmode="numeric"
               autocomplete="off"
               aria-haspopup="dialog"
               aria-expanded="false"
               placeholder="<?= h($placeholder ?? $defaults['placeholder']) ?>">
        <span class="ov-date-utc" aria-hidden="true">UTC</span>
        <?php if ($clearable): ?>
            <button type="button" class="ov-date-btn d-none" data-date-clear
                    title="<?= h($labels['clear']) ?>" aria-label="<?= h($labels['clear']) ?>">
                <i class="fas fa-xmark"></i>
            </button>
        <?php endif; ?>
        <button type="button" class="ov-date-btn" data-date-toggle
                title="<?= h($labels['open']) ?>" aria-label="<?= h($labels['open']) ?>">
            <i class="fas fa-chevron-down"></i>
        </button>
    </div>
    <?= $this->Form->text($field, array_merge([
        'id' => $inputId,
        'value' => $current,
        'class' => 'd-none',
        'tabindex' => -1,
        'aria-hidden' => 'true',
        'autocomplete' => 'off',
        'required' => false,
        'data-date-value' => '1',
    ], $inputAttrs ?? [])) ?>
</div>
