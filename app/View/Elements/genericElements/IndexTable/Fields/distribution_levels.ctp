<?php
$quickedit = isset($field['quickedit']) && $field['quickedit'];
if ($quickedit) {
    $object = Hash::extract($row, $field['data']['object']['value_path']);
    $event = Hash::extract($row, 'Event');
    $objectId = h($object['id']);
    $scope = $field['data']['scope'];
}

$distributionLevel = (Hash::extract($row, $field['data_path'])[0]);

echo sprintf('<div %s>', $quickedit ? sprintf(
    " onmouseenter=\"quickEditHover(this, '%s', %s, 'distribution', %s);\"",
    $scope,
    $objectId,
    $event['id']
)  : '');

if ($quickedit) {
    echo sprintf("<div id='%s_%s_distribution_placeholder' class='inline-field-placeholder'></div>", $scope, $objectId);
    echo sprintf("<div id='%s_%s_distribution_solid' class='inline-field-solid'>", $scope, $objectId);
}

echo sprintf(
    '<span class="%s bold">%s</span>',
    $distributionLevel == 0 ? 'red' : '',
    $distributionLevel != 4 ? $distributionLevels[$distributionLevel] :
        sprintf(
            '<a href="%s/sharing_groups/view/%s">%s</a>',
            $baseurl,
            h($row['SharingGroup']['id']),
            h($row['SharingGroup']['name'])
        )
);
if ($quickedit) {
    echo '</div></div>';
}
