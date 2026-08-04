<?php
    echo $this->Form->create('Attribute', array(
      'id' => 'Attribute' . '_' . $object['id'] . '_last_seen_form',
      'url' => '/attributes/editField/' . $object['id']
    ));
    echo $this->Form->input('last_seen', array(
        'label' => false,
        'type' => 'text',
        'value' => 0,
        'id' => 'Attribute' . '_' . $object['id'] . '_last_seen_field',
        'div' => false
    ));
    echo $this->Form->end();
?>
</div>
