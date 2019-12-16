<div class="generic-picker-embeded-block">
    <?php
        $url = '/objects/quickAddAttributeForm/' . $object['id'];
        $element = $template_element;
        $k = 0;
        $action = 'add';
        echo $this->Form->create('Object', array(
            'id' => 'Object_' . $object['id'] . '_quick_add_attribute_form',
            'url' => $url,
            'class' => 'allDiv'
        ));
    ?>

    <fieldset>
        <legend><?php echo __('Add Object attribute'); ?></legend>
        <div class="add_attribute_fields">
        <?php
            $formSettings = array(
                'type' => 'hidden',
                'value' => $element['object_relation'],
                'label' => false,
                'div' => false
            );
            echo $this->Form->input('Attribute.' . $k . '.object_relation', $formSettings);

            $formSettings['value'] = $object['id'];
            echo $this->Form->input('Object.id', $formSettings);

            $formSettings['value'] = $object['event_id'];
            echo $this->Form->input('Object.event_id', $formSettings);

            $formSettings['value'] = $element['type'];
            echo '<div style="margin-bottom: 5px; font-size: 14px;">';
            echo $this->Form->input('Attribute.' . $k . '.type', $formSettings);
            echo '<span class="bold">' . Inflector::humanize(h($element['object_relation'])) . '</span>';
            echo ' :: ' . h($element['type']) . '';
            echo '<br>';
            echo '<span class="immutableAttributeDescription">' . h($element['description']) . '</span>';
            echo '</div>';
        ?>


        <?php
            $formSettings = array(
              'options' => array_combine($element['categories'], $element['categories']),
              'default' => $element['default_category'],
              'div' => true
            );
            echo $this->Form->input('Attribute.' . $k . '.category', $formSettings);
        ?>

        <div class='input'>
        <?php
            echo $this->Form->input('Attribute.' . $k . '.distribution', array(
                'class' => 'Attribute_distribution_select',
                'options' => $distributionData['levels'],
                'default' => !empty($element['distribution']) ? $element['distribution'] : $distributionData['initial'],
                'div' => false,
                'label' => __('Distribution ') . $this->element('formInfo', array('type' => 'distribution')),
            ));
        ?>
        </div>
        <div class='input'>
            <div id="SGContainer" style="display:none;">
                <?php
                    if (!empty($distributionData['sgs'])) {
                        echo $this->Form->input('Attribute.' . $k . '.sharing_group_id', array(
                                'options' => $distributionData['sgs'],
                                'label' => __('Sharing Group')
                        ));
                    }
                ?>
            </div>
        </div>

        <div class="clear">
        <?php
            echo '<label for="Attribute' . $k . '.value">' . __('Value') . '</label>';
            echo $this->element(
                'Objects/object_value_field',
                array(
                    'element' => $element,
                    'k' => $k,
                    'action' => $action
                )
            );
        ?>
        </div>

        <?php
            echo $this->Form->input('Attribute.' . $k . '.to_ids', array(
                'type' => 'checkbox',
                'checked' => $element['to_ids'],
            ));
        ?>

        <?php
            echo $this->Form->input('Attribute.' . $k . '.disable_correlation', array(
                'type' => 'checkbox',
                'checked' => $element['disable_correlation'],
            ));
        ?>

        <?php
            echo $this->Form->input('Attribute.' . $k . '.comment', array(
                'type' => 'textarea',
                'required' => false,
                'allowEmpty' => true,
                'div' => 'input clear',
                'class' => 'input-xxlarge'
            ));
        ?>

       </div>
       </fieldset>

        <div class="overlay_spacing">
        <?php if ($ajax): ?>
            <span id="submitButton" class="btn btn-primary" style="margin-bottom:5px;float:left;" title="<?php echo __('Submit'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Submit'); ?>" onClick="submitPopoverForm('<?php echo h($object['id']); ?>', 'quickAddAttributeForm', <?php echo h($object['event_id']); ?>, 0, $(this).closest('div.popover').attr('data-dismissid'))"><?php echo __('Submit'); ?></span>
        <?php else:
                echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
            endif;
        ?>
        </div>

    <?php
        echo $this->Form->end();
    ?>
</div>

<script>
<?php
    $formInfoTypes = array('distribution' => 'Distribution');
    echo 'var formInfoFields = ' . json_encode($formInfoTypes) . PHP_EOL;
    foreach ($formInfoTypes as $formInfoType => $humanisedName) {
        echo 'var ' . $formInfoType . 'FormInfoValues = {' . PHP_EOL;
        foreach ($info[$formInfoType] as $key => $formInfoData) {
            echo '"' . $key . '": "<span class=\"blue bold\">' . h($formInfoData['key']) . '</span>: ' . h($formInfoData['desc']) . '<br />",' . PHP_EOL;
        }
        echo '}' . PHP_EOL;
    }
?>

$(document).ready(function() {
    initPopoverContent('Attribute0');
    $('#Attribute0Distribution').change(function() {
        initPopoverContent('Attribute0');
        if ($('#Attribute0Distribution').val() == 4) $('#SGContainer').show();
        else $('#SGContainer').hide();
    });
});
</script>
