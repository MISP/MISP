<?php
    $headersHtml = '';
    foreach ($fields as $k => $header) {
        if (isset($header['requirement']) && $header['requirement'] === false) {
            continue;
        }
        $header_data = '';
        if (!empty($header['sort'])) {
            if (!empty($header['name'])) {
                $header_data = $paginator->sort($header['sort'], $header['name']);
            } else {
                $header_data = $paginator->sort($header['sort']);
            }
        } else {
            if (!empty($header['element']) && $header['element'] === 'selector') {
                $header_data = sprintf(
                    '<input class="%s" type="checkbox" %s>',
                    empty($header['select_all_class']) ? 'select_all' : $header['select_all_class'],
                    empty($header['select_all_function']) ? 'onclick="toggleAllAttributeCheckboxes();"' : 'onclick="' . $header['select_all_function'] . '"'
                );
            } else {
                $header_data = h($header['name']);
            }

        }
        $headersHtml .= sprintf(
            '<th>%s</th>',
            $header_data
        );
    }
    if ($actions) {
        $headersHtml .= sprintf(
            '<th class="actions">%s</th>',
            __('Actions')
        );
    }
    $thead = '<thead>';
    $thead .= $headersHtml;
    $thead .= '</thead>';
    echo $thead;
?>
