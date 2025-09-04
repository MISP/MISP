<?php
    $headersHtml = '';
    $headerName = '';
    foreach ($fields as $k => $header) {
        if (!isset($header['requirement']) || $header['requirement']) {
            $header_data = '';
            $icon_html = '';
            if (!empty($header['icon'])) {
                $icon_html = $this->Bootstrap->icon($header['icon'], ['class' => ['d-inline me-1', 'link-light']]);
            }
            if (!empty($header['sort'])) {
                if (!empty($header['name'])) {
                    $header_data = $paginator->sort(
                        $header['sort'],
                        sprintf('%s%s', $icon_html, h($header['name'])),
                        ['escape' => false, 'class' => 'link-light']
                    );
                    $headerName = $header['name'];
                } else {
                    if (empty($icon_html)) {
                        $header_data = $paginator->sort($header['sort']);
                    } else {
                        $header_data = $paginator->sort(
                            $header['sort'],
                            $icon_html,
                            ['escape' => false]
                        );
                    }
                }
            } else {
                if (!empty($header['element']) && $header['element'] === 'selector') {
                    $header_data = sprintf(
                        '<input id="select_all" class="%s" type="checkbox" %s>',
                        empty($header['select_all_class']) ? 'select_all' : $header['select_all_class'],
                        empty($header['select_all_function']) ? 'onclick="toggleAllAttributeCheckboxes(this);"' : 'onclick="' . $header['select_all_function'] . '"'
                    );
                } else {
                    $header_data = h($header['name']);
                    $headerName = $header['name'];
                }

            }
            if (!empty($header['element']) && $header['element'] === 'selector') {
                $columnName = 'row-selector';
            } else {
                $columnName = h(\Inflector::variable(!empty($header['name']) ? $header['name'] : \Inflector::humanize($header['data_path'])));
            }
            $headersHtml .= sprintf(
                '<th scope="col" class="header text-light bg-dark" data-columnname="%s" %s>%s</th>',
                $columnName,
                empty($header['header_title']) ? 'title="' . h($headerName) . '"' : 'title="' . h($header['header_title']) . '"',
                $header_data
            );
        }
    }
    if ($actions) {
        $headersHtml .= sprintf(
            '<th scope="col"  class="actions text-end header text-light bg-dark">%s</th>',
            __('Actions')
        );
    }
    $thead = '<thead style="position: sticky;top:0">';
    $thead .= $headersHtml;
    $thead .= '</thead>';
    echo $thead;
?>
