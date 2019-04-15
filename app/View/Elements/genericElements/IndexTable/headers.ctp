<?php
    $headersHtml = '';
    foreach ($fields as $k => $header) {
        $header_data = '';
        if (!empty($header['sort'])) {
            if (!empty($header['name'])) {
                $header_data = $paginator->sort($header['sort'], $header['name']);
            } else {
                $header_data = $paginator->sort($header['sort']);
            }
        } else {
            $header_data = h($header['name']);
        }
        $headersHtml .= sprintf(
            '<th>%s</th>',
            $header_data
        );
    }
    echo $headersHtml;
?>
