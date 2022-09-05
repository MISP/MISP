<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");'));?>
    <fieldset>
            <legend><?php echo __('Propose Attachment'); ?></legend>
    <?php
        echo $this->Form->hidden('event_id');
        $categoryFormInfo = $this->element('genericElements/Form/formInfo', [
            'field' => [
                'field' => 'category'
            ],
            'modelForForm' => 'ShadowAttribute',
            'fieldDesc' => $fieldDesc['category'],
        ]);
        echo $this->Form->input('category', array(
            'default' => 'Payload delivery',
            'label' => __('Category ') . $categoryFormInfo,
        ));
        echo $this->Form->input('comment', array(
                'type' => 'text',
                'label' => __('Contextual Comment'),
                'error' => array('escape' => false),
                'div' => 'input clear',
                'class' => 'input-xxlarge'
        ));
        ?>
            <div class="input clear">
        <?php
        echo $this->Form->file('value', array(
            'error' => array('escape' => false),
        ));
        ?>
            </div>
            <div class="input clear"></div>
        <?php
        echo $this->Form->input('malware', array(
                'type' => 'checkbox',
                'checked' => false,
                'label' => __('Is a malware sample')
        ));
    ?>
    </fieldset>
<?php
    echo $this->Form->button(__('Propose'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttachment', 'event' => $event));
?>

<script>
var formZipTypeValues = <?= json_encode($isMalwareSampleCategory) ?>;

$(function() {
    $('#ShadowAttributeCategory').change(function() {
        malwareCheckboxSetter('ShadowAttribute');
    });
});
</script>

