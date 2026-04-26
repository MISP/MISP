<?php
/*
 * IndexTable field element rendering the misp_default flag as a
 * coloured badge. Used by app/View/EventTemplates/index.ctp on the
 * default theme to surface library-managed rows. Renders nothing
 * when the flag is 0 (locally authored or operator-forked).
 */
$flag = (int)Hash::get($row, $field['data_path']);
if ($flag === 1) {
    printf(
        '<span class="label label-info" title="%s">'
        . '<i class="fa fa-cube"></i> %s</span>',
        h(__('This template is managed by the misp-event-templates submodule. The library-update flow may overwrite it on every upstream version bump. Flip the misp_default flag off to fork.')),
        h(__('Library'))
    );
} else {
    echo '<span class="muted" style="color:#aaa; font-size:11px;">'
        . h(__('local'))
        . '</span>';
}
?>
