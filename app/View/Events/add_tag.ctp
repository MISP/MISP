<?php
$url = sprintf(
    '/%s/%s/%s%s',
    h(Inflector::tableize($scope)),
    'addTag',
    h($object_id),
    $local ? '/local:1' : ''
);
echo $this->Form->create($scope === 'Attribute' ? 'MispAttribute' : $scope, ['url' => $url]);
if ($scope === 'Attribute') {
    echo $this->Form->input('Attribute.attribute_ids', []);
}
echo $this->Form->input("$scope.tag", ['value' => 0]);
echo $this->Form->end();
