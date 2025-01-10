<?php
$path = $this->Hash->extract($data, $field['path']);
$pathName = $this->Hash->extract($data, $field['pathName']);
if (!empty($path) && !empty($pathName)) {
    $id = $this->Hash->extract($data, $field['path'])[0];
    $pathName = $this->Hash->extract($data, $field['pathName'])[0];
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
