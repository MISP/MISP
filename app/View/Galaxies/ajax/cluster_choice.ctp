<div class="hidden">
    <?php
        echo $this->Form->create('Galaxy', array('url' => '/galaxies/attachMultipleClusters/' . $target_type . '/' . $target_id, 'style' => 'margin:0px;'));
        echo $this->Form->input('target_ids', array('type' => 'text'));
        echo $this->Form->end();
    ?>
</div>

<?php echo $this->element('generic_picker'); ?>
