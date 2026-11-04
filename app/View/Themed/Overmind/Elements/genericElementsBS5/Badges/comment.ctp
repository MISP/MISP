<?php
/*
 * A record's comment, or a description shown as one: a muted line led by the
 * comment glyph, cut to one line with the whole text in the title. Every
 * comment of the theme goes through here; attribute-elements.css draws it.
 *
 * Expected:
 * $comment (string)
 *
 * Optional:
 * $inline (bool)   one item of an inline meta line rather than a line of its own
 * $column (bool)   the whole content of a table column: as wide as its text, up to a cap
 * $class (string)  the page's layout hook (margins, indent)
 */

$comment = trim((string)($comment ?? ''));
if ($comment === '') {
    return;
}
$tag = empty($inline) ? 'div' : 'span';
$classes = 'om-comment'
    . (empty($inline) ? '' : ' is-inline')
    . (empty($column) ? '' : ' is-column')
    . (empty($class) ? '' : ' ' . $class);
?>
<<?= $tag ?> class="<?= h($classes) ?>" title="<?= h($comment) ?>"><i class="fas fa-comment" aria-hidden="true"></i><?= h($comment) ?></<?= $tag ?>>
