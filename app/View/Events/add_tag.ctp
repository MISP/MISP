<?php
    echo $this->Form->create($scope, array('url' => array('controller' => Inflector::tableize($scope), 'action' => 'addTag', $object_id)));
    if ($scope === 'Attribute') {
        echo $this->Form->input('attribute_ids', array());
    }
    echo $this->Form->input('tag', array('value' => 0));
    echo $this->Form->end();
?>
