<?php
    echo $this->Form->create('Attribute', array(
      'id' => 'Attribute' . '_' . $object['id'] . '_first_seen_form',
      'url' => '/attributes/editField/' . $object['id']
    ));
?>
<?php
    echo $this->Form->input('first_seen', array(
        'label' => false,
        'type' => 'text',
        'value' => 0,
        'id' => 'Attribute' . '_' . $object['id'] . '_first_seen_field',
        'div' => false
    ));
    echo $this->Form->end();
?>
</div>
