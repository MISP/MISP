<?php
    echo $this->Form->create('Object', array('id' => 'Object' . '_' . $object['id'] . '_first_seen_form', 'url' => '/objects/editField/' . $object['id']));
?>
<?php
    echo $this->Form->input('first_seen', array(
            'label' => false,
            'type' => 'text',
            'value' => 0,
            'id' => 'Object' . '_' . $object['id'] . '_first_seen_field',
            'div' => false
    ));
    echo $this->Form->end();
?>
</div>
