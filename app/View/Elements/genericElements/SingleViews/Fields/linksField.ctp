<?php

$links = Hash::extract($data, $field['path']);

foreach ($links as &$link) {
    $link = sprintf(
        '<a href="%s">%s</a>',
        h($link),
        $link
    );
}

echo implode('<br />', $links);
