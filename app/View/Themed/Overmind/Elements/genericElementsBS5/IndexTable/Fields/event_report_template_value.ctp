<?php
/*
 * The body a report template variable expands to.
 *
 * Three shapes, because one shape cannot serve all three cases the table
 * actually holds:
 *
 *   empty       a muted placeholder — an unset value is a state, not a blank
 *               cell the reader has to interpret.
 *   one-liner   an inline code chip. Most variables are a single short string
 *               and giving each one a full framed block makes a four-row table
 *               look like a wall.
 *   a block     a framed, wrapping code block clamped to a few lines with a
 *               fade, its size, and a toggle that the delegated listener in
 *               the index reveals only when the text really is clipped. The
 *               line count is stated only when there is more than one — a
 *               wrapped paragraph reading "1 line" is noise, not a fact.
 *
 */
$value = Hash::get($row, $field['data_path']);
$value = $value === null ? '' : (string)$value;

if (trim($value) === '') {
    echo '<span class="small fst-italic text-secondary">' . __('no content') . '</span>';
    return;
}

$maxLength = 1500;
$maxLines = 40;

$chars = mb_strlen($value);
$lines = substr_count($value, "\n") + 1;

$text = $value;
$truncated = false;
if ($chars > $maxLength) {
    $text = mb_substr($text, 0, $maxLength);
    $truncated = true;
}
if (substr_count($text, "\n") >= $maxLines) {
    $text = implode("\n", array_slice(explode("\n", $text), 0, $maxLines));
    $truncated = true;
}

// A single short string is a chip, not a document.
if ($lines === 1 && $chars <= 120) {
    echo '<code class="d-inline-block mw-100 px-1 rounded bg-body-tertiary text-body small">'
        . h($value) . '</code>';
    return;
}
?>
<div class="erv-value">
    <pre class="erv-code mb-0 px-2 py-1 rounded border bg-body-tertiary small lh-sm"><?= h($text) ?><?= $truncated ? "\n…" : '' ?></pre>
    <button type="button" class="erv-more btn btn-link btn-sm p-0 pt-1 text-decoration-none fw-semibold d-none">
        <i class="fas fa-chevron-down erv-more-icon" aria-hidden="true"></i>
        <span class="erv-more-label"><?= __('Show more') ?></span>
    </button>
    <div class="d-flex flex-wrap gap-3 mt-1 small text-secondary">
        <?php if ($lines > 1): ?>
            <span><?= __n('%s line', '%s lines', $lines, $lines) ?></span>
        <?php endif; ?>
        <span><?= __n('%s character', '%s characters', $chars, $chars) ?></span>
        <?php if ($truncated): ?>
            <span class="text-warning-emphasis" title="<?= h(__('Only the first %s characters / %s lines are rendered here — open the variable to read all of it.', $maxLength, $maxLines)) ?>">
                <i class="fas fa-scissors opacity-50" aria-hidden="true"></i> <?= __('preview truncated') ?>
            </span>
        <?php endif; ?>
    </div>
</div>
