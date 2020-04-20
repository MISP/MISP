<?php
$extendbyData = Hash::extract($row, $field['fields']['extendby_data_path']);
$extendfromData = Hash::extract($row, $field['fields']['extendfrom_data_path']);
if (!empty($extendfromData)) {
    echo $this->element(
        '/genericElements/IndexTable/Fields/extended_from',
        array(
            'field' => $field,
            'row' => $row,
            'column' => $column,
            'data_path' => empty($field['data_path']) ? '' : $field['data_path'],
            'k' => $k
        )
    );
}

if (!empty($extendbyData)) {
    $field['parent'] = '';
    echo $this->element(
        '/genericElements/IndexTable/Fields/extended_by',
        array(
            'field' => $field,
            'row' => $row,
            'column' => $column,
            'data_path' => empty($field['data_path']) ? '' : $field['data_path'],
            'k' => $k
        )
    );
}
?>
