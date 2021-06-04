<?php
$id = Hash::extract($data, $field['path'])[0];
$pathName = Hash::extract($data, $field['pathName'])[0];
echo sprintf(
    '<a href="%s/%s/view/%s">%s</a>',
    $baseurl,
    $field['model'],
    h($id),
    h($pathName)
);
