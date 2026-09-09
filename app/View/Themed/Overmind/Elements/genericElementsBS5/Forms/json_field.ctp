<?php
/*
 * A box that takes a JSON document: the toolbar with the validity badge and
 * the Format button, the bordered editor with its line-number gutter, the one
 * error line, and the hint under it.
 *
 * Required params:
 *   $field   string|false  the form field the textarea posts as; false renders
 *                          a bare <textarea> (a box a script reads, that no
 *                          form submits) and then $id is required
 *
 * Optional params:
 *   $label        string   section label (default __('JSON'))
 *   $accent       string   accent key, see ModalAccent (default 'primary')
 *   $required     bool     REQUIRED badge, and a submit the field can refuse
 *   $shape        string   'any' | 'object' | 'array' — what the endpoint
 *                          accepts at the top level (default 'any')
 *   $xml          bool     the endpoint takes an XML document here too, and
 *                          tells the two apart by the first character the way
 *                          EventsController::add_misp_export() does. A value
 *                          opening with '<' is then accepted as it is rather
 *                          than parsed, so the box does not call a legitimate
 *                          XML export invalid. (default false)
 *   $id           string   textarea id (default: the one FormHelper derives)
 *   $value        mixed    prefill; an array is encoded, a string is
 *                          pretty-printed when it parses and left untouched
 *                          when it does not, so a broken value stays
 *                          repairable. Omit it and the field takes what
 *                          FormHelper holds for $field.
 *   $placeholder  string   the shape of a good value, not a description
 *   $rows         int      default 10
 *   $minHeight    string   CSS length for the editor (default '220px')
 *   $hint         string   field_hint text under the field
 *   $emptyLabel   string   badge wording while the box is empty
 *                          (default __('Waiting for input'))
 *   $reset        mixed    JSON to restore behind a Reset button (null: none)
 *   $gutter       bool     line numbers (default true; false for a 3-row box)
 *   $preview      bool     render the empty box a host script fills from the
 *                          parsed value through setPreview() (default false)
 *   $previewLabel string   label above that box
 *   $toolbar      string   extra HTML in the toolbar, before Format
 *   $above        string   extra HTML between the toolbar and the editor —
 *                          where a palette of snippets to insert belongs
 *                          (capture it with ob_start() in the view)
 *   $inputAttrs   array    merged into the textarea (data-*, aria-*, …)
 *   $class        string   classes on the wrapper (default 'w-100')
 *
 */

$field = isset($field) ? $field : false;
$accentKey = $accent ?? 'primary';
$accent = $this->ModalAccent->get($accentKey);
$shape = in_array($shape ?? 'any', ['any', 'object', 'array'], true)
    ? ($shape ?? 'any')
    : 'any';
$gutter = $gutter ?? true;
$allowXml = !empty($xml);

/* Stored minified, edited pretty-printed. An unparseable value is shown as it
 * is: reformatting it would need parsing it, and it is precisely what has to
 * be read by hand to be fixed. An XML one is never touched. */
$prefill = isset($value)
    ? $value
    : ($field === false ? null : $this->Form->value($field));
if (is_array($prefill) || is_object($prefill)) {
    $prefill = json_encode($prefill, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} elseif (is_string($prefill) && trim($prefill) !== ''
    && !($allowXml && substr(ltrim($prefill), 0, 1) === '<')
) {
    $decoded = json_decode($prefill);
    if (json_last_error() === JSON_ERROR_NONE) {
        $prefill = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
$prefill = is_string($prefill) ? $prefill : '';

$resetValue = null;
if (isset($reset) && $reset !== null && $reset !== false) {
    $resetValue = is_string($reset)
        ? $reset
        : json_encode($reset, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $decodedReset = json_decode($resetValue);
    if (json_last_error() === JSON_ERROR_NONE) {
        $resetValue = json_encode($decodedReset, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}

/* The textarea. `$field === false` means no form is involved, so FormHelper —
 * which would also lock the value into the Security token — stays out of it. */
/* No 'spellcheck' => 'false' here: CakePHP 2 lists spellcheck among its
 * minimized attributes (Helper::$_minimizedAttributes), so a 'false' value
 * renders as nothing at all — which is why every JSON box in the theme has
 * been spellchecked despite asking not to be. initJsonFields() sets the
 * property instead. */
$inputOptions = array_merge([
    'id' => $id ?? null,
    'class' => 'ov-json-input',
    'rows' => $rows ?? 10,
    'autocomplete' => 'off',
    'autocapitalize' => 'off',
    'data-json-input' => '1',
], $inputAttrs ?? []);
if (isset($placeholder)) {
    $inputOptions['placeholder'] = $placeholder;
}
if ($inputOptions['id'] === null) {
    unset($inputOptions['id']);
}
if ($field === false) {
    /* Without an id there is nothing for the host script to read. */
    $inputOptions['id'] = $inputOptions['id'] ?? 'jsonField';
    $inputOptions['spellcheck'] = 'false';
} else {
    $inputOptions['value'] = $prefill;
    $inputOptions['label'] = false;
    $inputOptions['div'] = false;
}

if ($field === false) {
    $attributes = '';
    foreach ($inputOptions as $key => $val) {
        if ($val === null || $val === false) {
            continue;
        }
        $attributes .= ' ' . h($key) . '="' . h($val) . '"';
    }
    $inputHtml = '<textarea' . $attributes . '>' . h($prefill) . '</textarea>';
} else {
    $inputHtml = $this->Form->textarea($field, $inputOptions);
}

/* FormHelper derives an id of its own when none was asked for, and the label
 * has to point at whatever it settled on. It is the only one that knows, so
 * read it back rather than guessing at the naming. */
$inputId = $inputOptions['id'] ?? null;
if ($inputId === null && preg_match('/\bid="([^"]+)"/', $inputHtml, $matches)) {
    $inputId = $matches[1];
}

/* Only meaningful to a host that named the field: it fills this box from a
 * misp:json-change, and the JS finds it by data attribute either way. */
$previewId = $inputId === null ? null : $inputId . 'Preview';

/* Everything the JS says about the value, translated here. */
$wordings = [
    'empty' => $emptyLabel ?? __('Waiting for input'),
    'valid' => __('Valid'),
    'invalid' => __('Invalid JSON'),
    'object' => __('The value has to be a JSON object.'),
    'array' => __('The value has to be a JSON array.'),
    'required' => __('Please fill this field in.'),
    'keys' => __('%s key(s)'),
    'items' => __('%s item(s)'),
    'line' => __('line %s'),
    /* The badge for a host's setProblem(): the document parsed, something in
     * it is still wrong. */
    'problem' => __('Check the content'),
    'xml' => __('XML document'),
];
?>
<div class="ov-json <?= h($class ?? 'w-100') ?>"
     data-json-field="1"
     data-json-shape="<?= h($shape) ?>"
     data-json-required="<?= empty($required) ? '0' : '1' ?>"
     <?php if ($allowXml): ?>data-json-xml="1"<?php endif; ?>
     <?php foreach ($wordings as $key => $text): ?>
     data-l-<?= h($key) ?>="<?= h($text) ?>"
     <?php endforeach; ?>
     style="--ov-json-accent: <?= $accent['colour'] ?>; --ov-json-min: <?= h($minHeight ?? '220px') ?>;">

    <div class="ov-json-head">
        <?= $this->element('genericElementsBS5/Forms/section_label', [
            'accent' => $accentKey,
            'label' => $label ?? __('JSON'),
            'required' => !empty($required),
            'for' => $inputId,
            'class' => 'mb-0',
        ]) ?>
        <div class="ov-json-tools">
            <?= $toolbar ?? '' ?>
            <span class="badge bg-secondary ov-json-status" data-json-status></span>
            <button type="button" class="btn btn-outline-secondary btn-sm ov-json-btn"
                    data-json-format
                    title="<?= h(__('Re-indent the document — it is left alone while it does not parse.')) ?>">
                <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Format') ?>
            </button>
            <?php if ($resetValue !== null): ?>
                <button type="button" class="btn btn-outline-secondary btn-sm ov-json-btn"
                        data-json-reset="<?= h($resetValue) ?>">
                    <i class="fas fa-rotate-left me-1"></i><?= __('Reset') ?>
                </button>
            <?php endif; ?>
        </div>
    </div>

    <?= $above ?? '' ?>

    <div class="ov-json-box" data-json-box>
        <?php if ($gutter): ?>
            <div class="ov-json-gutter" data-json-gutter aria-hidden="true">
                <div class="ov-json-gutter-inner"></div>
            </div>
        <?php endif; ?>
        <?= $inputHtml ?>
    </div>

    <div class="ov-json-error d-none" data-json-error>
        <i class="fas fa-circle-exclamation"></i><span></span>
    </div>

    <?php if (!empty($hint)): ?>
        <?= $this->element('genericElementsBS5/Forms/field_hint', ['text' => $hint]) ?>
    <?php endif; ?>

    <?php if (!empty($preview)): ?>
        <div class="d-none" data-json-preview-wrap>
            <?php if (!empty($previewLabel)): ?>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => $accentKey,
                    'label' => $previewLabel,
                    'class' => 'mb-1 mt-3',
                ]) ?>
            <?php endif; ?>
            <div class="ov-json-preview"<?= $previewId === null ? '' : ' id="' . h($previewId) . '"' ?> data-json-preview></div>
        </div>
    <?php endif; ?>

</div>
