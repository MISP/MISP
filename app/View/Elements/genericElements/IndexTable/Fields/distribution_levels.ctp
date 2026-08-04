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

if (empty($sg)) {
    $sgHtml = sprintf(
        '<span class="red bold" title="%s">%s</span>',
        __('your organisation is the local owner of this event, however it is not explicitly listed in the sharing group.'),
        __('Undisclosed sharing group')
    );
} else {
    $sgHtml = sprintf(
        '<a href="%s/sharing_groups/view/%s">%s</a>',
        $baseurl,
        h($sg['id']),
        h($sg['name'])
    );
}
echo sprintf(
    '<span class="%s">%s</span>',
    $distributionLevel == 0 ? 'red bold' : '',
    $distributionLevel != 4 ? $distributionLevels[$distributionLevel] : $sgHtml
);
if ($quickedit) {
    echo '</div></div>';
}
