<div class="shadow_attributes <?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<?php echo $this->Form->create('ShadowAttribute');?>
    <fieldset>
        <legend><?php echo __('Add Proposal'); ?></legend>
    <?php
        echo $this->Form->input('id');
        $categoryFormInfo = $this->element('genericElements/Form/formInfo', [
            'field' => [
                'field' => 'category'
            ],
            'modelForForm' => 'ShadowAttribute',
            'fieldDesc' => $fieldDesc['category'],
        ]);
        echo $this->Form->input('category', array(
            'empty' => __('(choose one)'),
            'div' => 'input',
            'label' => __('Category ') . $categoryFormInfo,
        ));
        $typeFormInfo = $this->element('genericElements/Form/formInfo', [
            'field' => [
                'field' => 'type'
            ],
            'modelForForm' => 'ShadowAttribute',
            'fieldDesc' => $fieldDesc['type'],
        ]);
        $typeInputData = array(
            'empty' => __('(first choose category)'),
            'label' => __('Type ') . $typeFormInfo,
        );
        if ($objectAttribute) {
            $typeInputData[] = 'disabled';
        }
        if (!$attachment) {
            echo $this->Form->input('type', $typeInputData);
        }
    ?>
    <div class="input clear"></div>
    <?php
        echo $this->Form->input('value', array(
            'type' => 'textarea',
            'error' => array('escape' => false),
            'class' => 'input-xxlarge clear'
        ));
        echo $this->Form->input('comment', array(
            'type' => 'text',
            'label' => __('Contextual Comment'),
            'error' => array('escape' => false),
            'div' => 'input clear',
            'class' => 'input-xxlarge'
        ));
    ?>
    <div class="input clear"></div>
    <?php
        echo $this->Form->input('to_ids', array(
                'label' => __('For Intrusion Detection System'),
        ));
        echo $this->Form->input('first_seen', array(
            'type' => 'text',
            'div' => 'input hidden',
            'required' => false,
        ));
        echo $this->Form->input('last_seen', array(
            'type' => 'text',
            'div' => 'input hidden',
            'required' => false,
        ));
    ?>
        <div id="bothSeenSliderContainer"></div>
    </fieldset>
    <p style="color:red;font-weight:bold;display:none;<?php if (isset($ajax) && $ajax) echo "text-align:center;"?>" id="warning-message"><?php echo __('Warning: You are about to share data that is of a sensitive nature (Attribution / targeting data). Make sure that you are authorised to share this.');?></p>
    <?php if (isset($ajax) && $ajax): ?>
        <div class="overlay_spacing">
            <table>
                <tr>
                <td style="vertical-align:top">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Propose');?>" title="<?php echo __('Propose');?>" id="submitButton" class="btn btn-primary" onClick="submitPopoverForm('<?php echo $event_id;?>', 'propose')"><?php echo __('Propose');?></span>
                </td>
                <td style="width:540px;">
                    <p style="color:red;font-weight:bold;display:none;<?php if (isset($ajax) && $ajax) echo "text-align:center;"?>" id="warning-message"><?php echo __('Warning: You are about to share data that is of a sensitive nature (Attribution / targeting data). Make sure that you are authorised to share this.');?></p>
                </td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" id="cancel_attribute_add"><?php echo __('Cancel');?></span>
                </td>
                </tr>
            </table>
        </div>
    <?php
        else:
            echo $this->Form->button('Propose', array('class' => 'btn btn-primary'));
        endif;
        echo $this->Form->end();
    ?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttribute', 'event' => $event));
    echo $this->element('form_seen_input');
?>

<script>
//
//Generate Category / Type filtering array
//
var category_type_mapping = <?= json_encode(array_map(function(array $value) {
    return $value['types'];
}, $categoryDefinitions)); ?>;

$(function() {
    $("#ShadowAttributeCategory").on('change', function(e) {
        formCategoryChanged('ShadowAttribute');
        if ($(this).val() === 'Attribution' || $(this).val() === 'Targeting data') {
            $("#warning-message").show();
        } else {
            $("#warning-message").hide();
        }
    });
});
</script>

