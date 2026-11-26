<?php
/*
 * The accented uppercase label that opens each field group inside a modal.
 *
 * Required params:
 *   $label     string  the label text
 *
 * Optional params:
 *   $accent    string  accent key, see ModalAccent (default 'primary')
 *   $required  bool    append the REQUIRED badge (default false)
 *   $badge     string  badge text, when it is not the word REQUIRED
 *   $for       string  render as a <label for="…"> rather than a <div>
 *   $class     string  spacing and any extra classes (default 'mb-2')
 */

$accent = $this->ModalAccent->get($accent ?? 'primary');
$badge = $badge ?? (empty($required) ? '' : __('REQUIRED'));
$tag = empty($for) ? 'div' : 'label';

/* The flex box only exists to seat the badge next to the text — a label
 * without one stays a plain block, as it was before this element. */
$classes = implode(' ', array_filter([
    $badge === '' ? '' : 'd-flex align-items-center gap-2',
    'fw-bold text-uppercase',
    $accent['textClass'],
    $class ?? 'mb-2',
]));
?>
<<?= $tag ?> class="<?= h($classes) ?>"<?= empty($for) ? '' : ' for="' . h($for) . '"' ?>
     style="font-size:.65rem; letter-spacing:.1em; <?= $accent['textStyle'] ?>"><?= h($label ?? '') ?><?php
if ($badge !== '') {
    printf(
        '<span class="%s" style="font-size:.55rem; opacity:.8; font-weight:700; %s">%s</span>',
        h(trim('badge ' . $accent['badgeClass'])),
        $accent['badgeStyle'],
        h($badge)
    );
}
?></<?= $tag ?>>
