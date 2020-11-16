<?php
$id = Hash::extract($data, $field['path'])[0];
$pathName = Hash::extract($data, $field['pathName'])[0];
echo sprintf(
    '<a href="%s/view/%s">%s</a>',
    $field['model'],
    h($id),
    h($pathName)
);
