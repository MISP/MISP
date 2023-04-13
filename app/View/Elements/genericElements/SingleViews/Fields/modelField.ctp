<?php
$path = Hash::extract($data, $field['path']);
$pathName = Hash::extract($data, $field['pathName']);
if (!empty($path) && !empty($pathName)) {
    $id = Hash::extract($data, $field['path'])[0];
    $pathName = Hash::extract($data, $field['pathName'])[0];
    echo sprintf(
        '<a href="%s/%s/view/%s">%s</a>',
        $baseurl,
        $field['model'],
        h($id),
        h($pathName)
    );
} else {
    echo empty($field['error']) ? '&nbsp;' : h($field['error']);
}
