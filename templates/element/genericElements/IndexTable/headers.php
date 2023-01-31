<?php
    $headersHtml = '';
    foreach ($fields as $k => $header) {
        if (!isset($header['requirement']) || $header['requirement']) {
            $header_data = '';
            $icon_html = '';
            if (!empty($header['icon'])) {
                $icon_html = $this->Bootstrap->icon($header['icon'], ['class' => ['d-inline me-1']]);
            }
            if (!empty($header['sort'])) {
                if (!empty($header['name'])) {
                    $header_data = $paginator->sort(
                        $header['sort'],
                        sprintf('%s%s', $icon_html, h($header['name'])),
                        ['escape' => false]
                    );
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
                }

            }
            if (!empty($header['element']) && $header['element'] === 'selector') {
                $columnName = 'row-selector';
            } else {
                $columnName = h(\Cake\Utility\Inflector::variable(!empty($header['name']) ? $header['name'] : \Cake\Utility\Inflector::humanize($header['data_path'])));
            }
            $headersHtml .= sprintf(
                '<th scope="col" data-columnname="%s">%s</th>',
                $columnName,
                $header_data
            );
        }
    }
    if ($actions) {
        $headersHtml .= sprintf(
            '<th class="actions text-end">%s</th>',
            __('Actions')
        );
    }
    $thead = '<thead>';
    $thead .= $headersHtml;
    $thead .= '</thead>';
    echo $thead;
?>
