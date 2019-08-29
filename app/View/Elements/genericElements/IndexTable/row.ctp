<?php
    $rowHtml = '';
    foreach ($fields as $field) {
        if (empty($field['element'])) {
            $valueField = $this->element('/genericElements/IndexTable/Fields/generic_field', array('field' => $field, 'row' => $row, 'data_path' => empty($field['data_path']) ? '' : $field['data_path'], 'k' => $k));
        } else {
            $valueField = $this->element(
                '/genericElements/IndexTable/Fields/' . $field['element'],
                array(
                    'field' => $field,
                    'row' => $row,
                    'data_path' => empty($field['data_path']) ? '' : $field['data_path'], 'k' => $k
                )
            );
        }
        $rowHtml .= sprintf(
            '<td%s%s%s%s%s%s%s>%s</td>',
            (empty($field['id'])) ? '' : sprintf('id="%s"', $field['id']),
            (empty($field['class'])) ? '' : sprintf(' class="%s"', $field['class']),
            (empty($field['style'])) ? '' : sprintf(' style="%s"', $field['style']),
            (empty($field['title'])) ? '' : sprintf(' title="%s"', $field['title']),
            (empty($field['name'])) ? '' : sprintf(' data-path="%s"', (h($field['data_path']))),
            (empty($field['encode_raw_value']) || empty($field['data_path'])) ? '' : sprintf(' data-value="%s"', (h(Hash::extract($row, $field['data_path'])[0]))),
            (empty($field['ondblclick'])) ? '' : sprintf(' ondblclick="%s"', $field['ondblclick']),
            $valueField
        );
    }
    if (!empty($actions)) {
        $rowHtml .= $this->element(
            '/genericElements/IndexTable/Fields/actions',
            array(
                'actions' => $actions,
                'row' => $row
            )
        );
    }
    echo ($rowHtml);
?>
