<?php
/*
 * role_permissions.ctp
 *
 * Compact "Permissions" cell. Replaces the historical one-boolean-column-per-flag
 * layout (24+ columns, horizontal scroll) with a single column that lists only
 * the *enabled* permissions as pills. Adding a new permission flag therefore adds
 * at most one more possible pill, never a new column.
 *
 * Expected:
 *   $field['data_path'] => path to the Role array (e.g. 'Role')
 *   $field['permFlags'] => Role::permFlags map (key => ['text', 'title', ...])
 *   $field['isAdmin']   => bool, controls whether the raw admin label is shown
 *
 * Overflow beyond $maxVisible pills is hidden behind a "+N" toggle reusing the
 * shared toggleTags() helper (see mispOvermind.js / tag_list.ctp).
 */
$role = Hash::get($row, $field['data_path']);
if (empty($role)) {
    return;
}

$permFlags  = $field['permFlags'] ?? [];
$isAdmin    = !empty($field['isAdmin']);
$maxVisible = 4;

// Site admin implies every other permission, so a single prominent pill says it all.
if (!empty($role['perm_site_admin'])) {
    echo sprintf(
        '<div class="d-inline-flex flex-wrap align-items-center gap-1">'
            . '<span class="badge rounded-pill text-bg-danger fw-semibold" title="%s">'
            . '<i class="fas fa-shield-halved me-1"></i>%s</span></div>',
        h($permFlags['perm_site_admin']['title'] ?? ''),
        __('Full access')
    );
    return;
}

$pills = [];
foreach ($permFlags as $k => $permFlag) {
    if ($k === 'perm_site_admin' || empty($role[$k])) {
        continue;
    }
    $pills[] = [
        'label' => $isAdmin ? $permFlag['text'] : Inflector::humanize(substr($k, 5)),
        'title' => $permFlag['title'] ?? '',
    ];
}

if (empty($pills)) {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}
?>
<div class="tag-container d-inline-flex flex-wrap align-items-center gap-1">
    <?php foreach ($pills as $i => $pill): ?>
        <span class="badge rounded-pill fw-normal text-bg-light border text-body <?= $i >= $maxVisible ? 'd-none extra-tag' : '' ?>"
              title="<?= h($pill['title']) ?>">
            <?= h($pill['label']) ?>
        </span>
    <?php endforeach; ?>

    <?php if (count($pills) > $maxVisible): ?>
        <span class="badge rounded-pill text-bg-secondary"
              style="cursor:pointer;"
              role="button"
              onclick="toggleTags(this)">
            +<?= count($pills) - $maxVisible ?>
        </span>
    <?php endif; ?>
</div>
