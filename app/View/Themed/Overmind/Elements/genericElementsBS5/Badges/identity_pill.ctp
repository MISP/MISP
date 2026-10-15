<?php
/*
 * A record's identity: one pill holding its #id and its UUID, each a button
 * that copies its value. Either half may be missing.
 *
 *   $id    int|string  the local id
 *   $uuid  string      the UUID
 *
 * A detail page does not echo this itself: it sets `headerIdentity` to its
 * record (only `id` and `uuid` are read) and headerSection puts the pill at
 * the head of the description line, whichever tab is open.
 */
$copyButton = function ($icon, $value, $title, $message) {
    return sprintf(
        '<button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center gap-1'
        . ' border-0 bg-transparent text-body-secondary px-2 mb-0"'
        . ' title="%s" aria-label="%s" data-copy-value="%s" data-copy-msg="%s"'
        . ' onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">'
        . '<i class="%s opacity-50"></i>%s<i class="fas fa-copy fa-xs"></i></button>',
        h($title),
        h($title),
        h($value),
        h($message),
        h($icon),
        h($value)
    );
};

$parts = [];
if (isset($id) && $id !== '') {
    $parts[] = $copyButton('fas fa-hashtag', $id, __('Copy ID'), __('ID copied to clipboard'));
}
if (!empty($uuid)) {
    $parts[] = $copyButton('fas fa-fingerprint', $uuid, __('Copy UUID'), __('UUID copied to clipboard'));
}
if (empty($parts)) {
    return;
}
?>
<span class="d-inline-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base">
    <?= implode('<span class="vr my-1"></span>', $parts) ?>
</span>
