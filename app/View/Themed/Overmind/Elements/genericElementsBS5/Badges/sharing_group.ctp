<?php

/*
 * Expected:
 * $sharingGroup (array) → at least 'id' and 'name'
 * $link (bool) → link to the sharing group view (default true)
 */

$sharingGroup = $sharingGroup ?? [];
$link = ($link ?? true) && !empty($sharingGroup['id']);

if (empty($sharingGroup['name'])) {
    return;
}

$content = '<span class="misp-icon misp-icon-sharing-group misp-hexagone text-primary"></span>'
    . '<span class="text-truncate min-w-0">' . h($sharingGroup['name']) . '</span>';
$classes = 'd-inline-flex align-items-center gap-1 fw-semibold mw-100';
?>
<?php if ($link): ?>
    <a href="<?= h($baseurl . '/sharing_groups/view/' . $sharingGroup['id']) ?>"
       class="<?= $classes ?> text-decoration-none"><?= $content ?></a>
<?php else: ?>
    <span class="<?= $classes ?>"><?= $content ?></span>
<?php endif; ?>
