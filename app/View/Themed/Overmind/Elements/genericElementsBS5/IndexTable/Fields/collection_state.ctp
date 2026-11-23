<?php
// Overmind collections index: the publish state as one glyph, as the events index draws it.
$collection = $row['Collection'] ?? [];
if ((int)($collection['distribution'] ?? 0) === 0) {
    printf(
        '<span class="te-st te-faint" role="img" title="%s" aria-label="%s">—</span>',
        h(__('Your organisation only: nothing to publish')),
        h(__('Your organisation only: nothing to publish'))
    );
    return;
}
$lastPublished = empty($collection['last_published']) ? '' : substr((string)$collection['last_published'], 0, 16);
$changes = $collection['changes'] ?? ['added' => 0, 'removed' => 0];
$count = (int)$changes['added'] + (int)$changes['removed'];
$changedSince = $lastPublished !== '' && !empty($collection['modified'])
    && strtotime($collection['modified']) > strtotime($collection['last_published']);
if (!empty($collection['published'])) {
    [$class, $icon] = ['is-pub', 'fa-circle-check'];
    $title = $lastPublished !== '' ? __('Published %s', $lastPublished) : __('Published');
} elseif ($lastPublished !== '' && ($count > 0 || $changedSince)) {
    [$class, $icon] = ['is-pending', 'fa-clock-rotate-left'];
    $title = __('Changes pending: published %s, changed since', $lastPublished);
} else {
    [$class, $icon] = ['is-unpub', 'fa-floppy-disk'];
    $title = $lastPublished !== '' ? __('Unpublished · last published %s', $lastPublished) : __('Unpublished');
}
if ($count > 0) {
    $title .= ' · ' . (!empty($collection['_canPublish'])
        ? __n('%s change not yet shared', '%s changes not yet shared', $count, $count)
        : __n('%s change waiting for a publisher', '%s changes waiting for a publisher', $count, $count));
}
printf(
    '<span class="te-st %s" role="img" title="%s" aria-label="%s"><i class="fas %s" aria-hidden="true"></i></span>',
    $class,
    h($title),
    h($title),
    $icon
);
