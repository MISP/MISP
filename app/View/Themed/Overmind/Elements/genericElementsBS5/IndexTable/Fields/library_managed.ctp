<?php
/*
 * BS5 IndexTable field renderer for the misp_default flag. Mirrors
 * the default-theme `library_managed.ctp` semantics (PRD §10.3):
 * library-managed rows get a primary badge, locally-authored rows
 * get a soft-grey "local" label.
 */
$flag = (int)Hash::get($row, $field['data_path']);
if ($flag === 1) {
    printf(
        '<span class="badge bg-primary-subtle text-primary border border-primary-subtle" '
        . 'title="%s"><i class="fas fa-cube me-1"></i>%s</span>',
        h(__('This template is managed by the misp-event-templates submodule. The library-update flow may overwrite it on every upstream version bump. Flip the misp_default flag off to fork.')),
        h(__('Library'))
    );
} else {
    echo '<span class="text-muted small">' . h(__('local')) . '</span>';
}
?>
