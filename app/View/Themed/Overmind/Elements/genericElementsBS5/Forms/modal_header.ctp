<?php
/*
 * The accented strip every modal in this theme opens with: an eyebrow, a title
 * with a glyph, an optional one-line explanation, and a large watermark glyph
 * on the right.
 *
 * Pair it with Forms/modal_footer. Between the two the template writes its own
 * body — this element deliberately does not create the form, so it also serves
 * the modals that have no form at all (the tag and galaxy pickers, the analyst
 * thread, the import and resolution screens).
 *
 * Required params:
 *   $eyebrow  string  small uppercase label above the title
 *   $title    string  the title itself
 *
 * Optional params:
 *   $accent       string  accent key, see ModalAccent (default 'primary')
 *   $description  string  muted one-liner under the title
 *   $icon         string  full class attribute of the right-hand watermark glyph
 *   $titleIcon    string  full class attribute of the glyph left of the title;
 *                         defaults to pen-to-square / circle-plus on $isEdit,
 *                         '' drops it
 *   $isEdit       bool    picks the default title glyph (default false)
 *   $titleId      string  id on the <h4>, for aria-labelledby
 *   $titleBadge   string  raw HTML placed inside the <h4> after the title — the
 *                         count and file-name pills the review screens carry;
 *                         escape it yourself
 *   $aside        string  raw HTML for the right-hand slot, replacing the
 *                         watermark glyph; escape it yourself
 *   $descriptionClass string  extra classes on the description, e.g. 'font-monospace'
 *   $close        bool    replace the watermark with a dismiss button (default false)
 *   $escape       bool    h() the three texts (default true — pass false only for
 *                         a description you have escaped yourself)
 */

$accent = $this->ModalAccent->get($accent ?? 'primary');
$isEdit = !empty($isEdit);
$escape = !isset($escape) || $escape;
$title = $title ?? '';
$eyebrow = $eyebrow ?? '';
$description = $description ?? '';
$icon = $icon ?? '';
$titleIcon = $titleIcon ?? ('fas fa-' . ($isEdit ? 'pen-to-square' : 'circle-plus'));
$close = !empty($close);

$text = function ($value) use ($escape) {
    return $escape ? h($value) : $value;
};

/* One accented glyph, at the size the strip wants it. The accent reaches it
 * through a Bootstrap utility when the scope has one and inline otherwise, so
 * both halves are assembled here rather than at each call site. */
$glyph = function ($classes, $size, $extra = '') use ($accent) {
    return sprintf(
        '<span class="%s" style="font-size:%s;%s%s"></span>',
        h(trim($classes . ' ' . $accent['textClass'])),
        $size,
        $extra,
        $accent['textStyle'] === '' ? '' : ' ' . $accent['textStyle']
    );
};
?>
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:<?= $accent['tint'] ?>; border-bottom:2px solid <?= $accent['line'] ?>;">
    <div>
        <?php if ($eyebrow !== ''): ?>
            <div class="<?= h(trim('text-uppercase fw-semibold mb-1 ' . $accent['textClass'])) ?>"
                 style="font-size:.58rem; letter-spacing:.12em; opacity:.85; <?= $accent['textStyle'] ?>"><?= $text($eyebrow) ?></div>
        <?php endif; ?>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2"<?= empty($titleId) ? '' : ' id="' . h($titleId) . '"' ?>>
            <?= $titleIcon === '' ? '' : $glyph($titleIcon, '1.25rem') ?>
            <?= $text($title) ?><?= $titleBadge ?? '' ?>
        </h4>
        <?php if ($description !== ''): ?>
            <p class="text-muted mb-0<?= empty($descriptionClass) ? '' : ' ' . h($descriptionClass) ?>"
               style="font-size:.75rem;"><?= $text($description) ?></p>
        <?php endif; ?>
    </div>
    <?php if (!empty($aside)): ?>
        <?= $aside ?>
    <?php elseif ($close): ?>
        <button type="button" class="btn-close" data-bs-dismiss="modal"
                aria-label="<?= __('Close') ?>"></button>
    <?php elseif ($icon !== ''): ?>
        <?= $glyph($icon, '2rem', ' opacity:.45;') ?>
    <?php endif; ?>
</div>
