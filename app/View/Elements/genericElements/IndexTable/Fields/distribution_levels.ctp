<?php
$quickedit = isset($field['quickedit']) && $field['quickedit'];
if ($quickedit) {
    $object = Hash::extract($row, $field['data']['object']['value_path']);
    $objectId = h($object['id']);
    $scope = $field['data']['scope'];
}

$distributionLevel = Hash::extract($row, $field['data_path'])[0];
if ($distributionLevel == 4) {
    $sg = empty($field['sg_path']) ? $row['SharingGroup'] : Hash::extract($row, $field['sg_path']);
}

echo sprintf('<div%s>', $quickedit ? sprintf(
    " onmouseenter=\"quickEditHover(this, '%s', %s, 'distribution');\"",
    $scope,
    $objectId
)  : '');

if ($quickedit) {
    echo "<div class='inline-field-solid'>";
}

echo sprintf(
    '<span class="%s">%s</span>',
    $distributionLevel == 0 ? 'red bold' : '',
    $distributionLevel != 4 ? $distributionLevels[$distributionLevel] :
        sprintf(
            '<a href="%s/sharing_groups/view/%s">%s</a>',
            $baseurl,
            h($sg['id']),
            h($sg['name'])
        )
);
if ($quickedit) {
    echo '</div></div>';
}
