<?php
    $url = '/objects/quickAddAttributeForm/' . $object['id'];
    $element = $template['ObjectTemplateElement'][0];
    $k = 0;
    echo $this->Form->create('Object', array(
        'id' => 'Object_' . $object['id'] . '_quick_add_attribute_form',
        'url' => $url
    ));

    echo $this->element('Objects/object_add_attributes',
        array(
            'element' => $element,
            'k' => $k,
            'action' => 'add',
            'enabledRows' => array(0)
        )
    );

    echo $this->Form->end();
?>

