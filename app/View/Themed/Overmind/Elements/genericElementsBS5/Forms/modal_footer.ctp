<?php
/*
 * The action bar every modal in this theme closes with: a muted context line on
 * the left, the buttons on the right.
 *
 * Pair it with Forms/modal_header. The buttons are plain <button> elements, not
 * $this->Form->button() — FormHelper adds nothing to a submit button, and going
 * through one path means a form-submitting modal and a JavaScript-driven one are
 * described the same way.
 *
 * Optional params — all of them:
 *   $accent    string  accent key, see ModalAccent (default 'primary'); colours
 *                      the submit button
 *   $isEdit    bool    picks the default submit label and glyph (default false)
 *
 *   -- left-hand context, first one set wins --
 *   $meta      array   chips, each ['label' =>, 'value' =>, 'mono' =>, 'note' =>],
 *                      rendered as `Label: **value**` and joined with a pipe.
 *                      'id' instead of 'value' prefixes it with a hash — a
 *                      record's id is what most of these chips carry
 *   $hint      string  a single line, prefixed with a circle-info glyph
 *   $metaHtml  string  raw HTML, for the few that fit neither — escape it yourself
 *   $metaId    string  id on the left-hand div, for the templates that rewrite
 *                      it from JavaScript
 *
 *   -- buttons, rendered left to right --
 *   $buttons   array        buttons before the cancel one — where a "Back"
 *                           belongs, since leaving comes before staying
 *   $cancel    array|false  the dismiss button; false drops it. Defaults to
 *                           "Discard" with data-bs-dismiss="modal"
 *   $secondary array        buttons between cancel and submit — a second action
 *                           on the same footing as the primary one ("Validate")
 *   $submit    array|false  the primary button; false drops it. Defaults to
 *                           "Save Changes" / "Add" in the accent colour
 *
 *   -- layout --
 *   $align     string  'between' (default) or 'end' — 'end' when there is no
 *                      left-hand context to balance the buttons
 *   $border    bool    draw the hairline above the bar (default true)
 *   $bleed     bool    true for a bar outside the body's padding (px-4 py-3)
 *                      rather than inside it (mt-4 pt-3)
 *
 * A button spec:
 *   label     string  the text
 *   labelHtml string  raw HTML instead of `label`, for a label JavaScript
 *                     rewrites through an inner element — escape it yourself
 *   icon      string  full class attribute of its glyph, '' for none
 *   class     string  replaces the default classes (`btn btn-sm` are always added)
 *   style     string  inline declarations
 *   id        string
 *   type      string  'button' (default) or 'submit'
 *   href      string  renders an <a> instead of a <button>
 *   disabled  bool
 *   attrs     array   any other attribute, e.g. ['onclick' => '…', 'title' => '…']
 */

$accent = $this->ModalAccent->get($accent ?? 'primary');
$isEdit = !empty($isEdit);
$isSplit = ($align ?? 'between') !== 'end';
$border = !isset($border) || $border;

/* Renders one button spec — an <a> when it carries an href, a <button>
 * otherwise. The modals that navigate away (Back, Cancel to an index) need the
 * former, everything else the latter. */
$renderButton = function (array $spec) {
    $tag = empty($spec['href']) ? 'button' : 'a';
    $attributes = ['class' => trim('btn btn-sm ' . ($spec['class'] ?? 'btn-outline-secondary'))];
    foreach (['style', 'id'] as $name) {
        if (!empty($spec[$name])) {
            $attributes[$name] = $spec[$name];
        }
    }
    $attributes += $tag === 'a'
        ? ['href' => $spec['href']]
        : ['type' => $spec['type'] ?? 'button'];
    $attributes += $spec['attrs'] ?? [];

    $rendered = '<' . $tag;
    foreach ($attributes as $name => $value) {
        $rendered .= sprintf(' %s="%s"', $name, h($value));
    }
    if (!empty($spec['disabled'])) {
        $rendered .= ' disabled';
    }
    $rendered .= '>';
    if (!empty($spec['icon'])) {
        $rendered .= sprintf('<i class="%s me-1"></i>', h($spec['icon']));
    }

    $rendered .= $spec['labelHtml'] ?? h($spec['label'] ?? '');

    return $rendered . '</' . $tag . '>';
};

/* One chip of the left-hand context line. */
$renderChip = function (array $chip) {
    $value = isset($chip['id']) ? '#' . $chip['id'] : ($chip['value'] ?? '');
    $rendered = empty($chip['label']) ? '' : h($chip['label']) . ': ';
    $rendered .= sprintf(
        empty($chip['mono']) ? '<strong class="text-body">%s</strong>' : '<code class="text-body">%s</code>',
        h($value)
    );
    if (!empty($chip['note'])) {
        $rendered .= ' ' . h($chip['note']);
    }

    return '<span>' . $rendered . '</span>';
};

/* The bar, in render order. `+` keeps what the caller set and fills in the
 * rest, so a spec overrides a default outright rather than merging into it. */
$bar = $buttons ?? [];

if (($cancel = $cancel ?? []) !== false) {
    $bar[] = $cancel + [
        'label' => __('Discard'),
        'icon' => 'fas fa-times',
        'attrs' => ['data-bs-dismiss' => 'modal'],
    ];
}

foreach ($secondary ?? [] as $spec) {
    $bar[] = $spec;
}

if (($submit = $submit ?? []) !== false) {
    $bar[] = $submit + [
        'label' => $isEdit ? __('Save Changes') : __('Add'),
        'icon' => 'fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus'),
        'class' => $accent['btnClass'],
        'style' => $accent['btnStyle'],
        'type' => 'submit',
    ];
}

$barClasses = sprintf(
    'd-flex align-items-center flex-wrap gap-2 %s %s',
    $isSplit ? 'justify-content-between' : 'justify-content-end',
    empty($bleed) ? 'mt-4 pt-3' : 'px-4 py-3'
);
?>
<div class="<?= $barClasses ?>"<?= $border ? ' style="border-top:1px solid var(--bs-border-color, #dee2e6);"' : '' ?>>
<?php if ($isSplit): ?>
    <div class="text-muted d-flex align-items-center gap-1 flex-wrap" style="font-size:.75rem;"<?= empty($metaId) ? '' : ' id="' . h($metaId) . '"' ?>><?php
        if (!empty($metaHtml)) {
            echo $metaHtml;
        } elseif (!empty($meta)) {
            echo implode('<span class="opacity-50">|</span>', array_map($renderChip, array_values($meta)));
        } elseif (!empty($hint)) {
            printf('<i class="fas fa-circle-info" style="font-size:.65rem;"></i>%s', h($hint));
        }
    ?></div>
<?php endif; ?>
<?php if (!empty($bar)): ?>
    <div class="d-flex gap-2"><?= implode('', array_map($renderButton, $bar)) ?></div>
<?php endif; ?>
</div>
