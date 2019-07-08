<?php
    $url = array('controller' => Inflector::tableize($scope), 'action' => 'addTag', $object_id);
    $url = sprintf(
        '/%s/%s/%s%s',
        h(Inflector::tableize($scope)),
        'addTag',
        h($object_id),
        $local ? '/local:1' : ''
    );
    echo $this->Form->create($scope, array('url' => $url));
    if ($scope === 'Attribute') {
        echo $this->Form->input('attribute_ids', array());
    }
    echo $this->Form->input('tag', array('value' => 0));
    echo $this->Form->end();
?>
