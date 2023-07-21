<?php
if ($scope === 'event') {
    echo '<span class="title-section">' . __('Galaxies') . '</span>';
}
echo $this->element('galaxyQuickViewNew', [
    'data' => $object['Galaxy'],
    'event' => $object,
    'target_id' => $scope == 'event' ? $object['Event']['id'] : $object['Attribute']['id'],
    'target_type' => $scope
]);
