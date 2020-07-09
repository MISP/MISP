<?php
/** 
 * Generate a tree like hierarchy from the provided data
 * 
 * @see tree_node.ctp
 * @param array $field['parent'] If provided, will be echoed verbatim
 * @param array $field['fields']['tree_data'] The data for each tree level, from parent to children:
 *          array(
 *              0 => array(
 *                  $tree_node_data
 *              ),
 *              1 => array(...),
 *          )
 */

if (isset($field['parent'])) {
    echo h($field['parent']);
} else {
    echo $this->element('/genericElements/IndexTable/Fields/generic_field', array(
        'row' => $row,
        'field' => $field
    ));
}

$htmlExtended = '';
$datapathLevels = $field['fields']['tree_data'];
$levelSkiped = 0;
foreach ($datapathLevels as $level => $datapathLevel) {
    $dataForLevel = Hash::extract($row, $datapathLevel['main_data_path']);
    if (!empty($dataForLevel)) {
        $htmlExtended .= $this->element(
            '/genericElements/IndexTable/Fields/tree_node',
            array(
                'datapath' => $datapathLevel,
                'data' => $dataForLevel,
                'level' => $level - $levelSkiped,
            )
        );
    } else {
        $levelSkiped++;
    }
}

if ($levelSkiped + 1 < count($datapathLevels)) { // only print if at least 2 level were displayed
    echo $htmlExtended;
}
?>
