<div class="hidden">
    <?php
        echo $this->Form->create('Galaxy', array('url' => '/galaxies/attachMultipleClusters/' . $target_id . '/' . $target_type, 'style' => 'margin:0px;'));
        echo $this->Form->input('target_ids', array('type' => 'text'));
        echo $this->Form->input('attribute_ids', array('style' => 'display:none;', 'label' => false));
        echo $this->Form->end();
    ?>
</div>

<?php echo $this->element('generic_picker'); ?>

<script>
    $(document).ready(function() {
        $('#GalaxyAttributeIds').attr('value', getSelected());
    });
</script>
