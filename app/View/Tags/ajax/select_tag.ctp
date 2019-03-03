<div style="display:none;">
    <?php
        if ($scope === 'attribute') {
            echo $this->Form->create('Attribute', array('url' => '/attributes/addTag/' . $object_id, 'style' => 'margin:0px;'));
        } elseif ($scope === 'event') {
            echo $this->Form->create('Event', array('url' => '/events/addTag/' . $object_id, 'style' => 'margin:0px;'));
        } elseif ($scope === 'tag_collection') {
            echo $this->Form->create('TagCollection', array('url' => '/tag_collections/addTag/' . $object_id, 'style' => 'margin:0px;'));
        }
        echo $this->Form->input('attribute_ids', array('style' => 'display:none;', 'label' => false));
        echo $this->Form->input('tag', array('value' => 0));
        echo $this->Form->end();
    ?>
</div>

<?php echo $this->element('generic_picker'); ?>
