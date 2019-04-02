<?php
    $rowHtml = '';
    foreach ($fields as $k => $field) {
        if (empty($field['element'])) {
            $valueField = $this->element('/genericElements/IndexTable/Fields/generic_field', array('field' => $field, 'row' => $row, 'data_path' => empty($field['data_path']) ? '' : $field['data_path']));
        } else {
            $valueField = $this->element('/genericElements/IndexTable/Fields/' . $field['element'], array('field' => $field, 'row' => $row, 'data_path' => empty($field['data_path']) ? '' : $field['data_path']));
        }
        $rowHtml .= sprintf(
            '<td%s%s%s%s%s>%s</td>',
            (empty($field['id'])) ? '' : sprintf('id="%s"', $field['id']),
            (empty($field['class'])) ? '' : sprintf(' class="%s"', $field['class']),
            (empty($field['style'])) ? '' : sprintf(' style="%s"', $field['style']),
            (empty($field['title'])) ? '' : sprintf(' title="%s"', $field['title']),
            (empty($field['ondblclick'])) ? '' : sprintf(' ondblclick="%s"', $field['ondblclick']),
            $valueField
        );
    }
    echo ($rowHtml);
?>
