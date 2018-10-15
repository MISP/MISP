<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("AttributeMalware").removeAttribute("disabled");'));?>
    <fieldset>
        <legend><?php echo __('Add Attachment(s)'); ?></legend>
        <?php
            echo $this->Form->hidden('event_id');
            echo $this->Form->input('category', array(
                'default' => 'Payload delivery',
                'label' => __('Category ') . $this->element('formInfo', array('type' => 'category'))
            ));
        ?>
        <div class="input clear"></div>
        <?php
                $initialDistribution = 5;
                if (Configure::read('MISP.default_attribute_distribution') != null) {
                    if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                        $initialDistribution = 5;
                    } else {
                        $initialDistribution = Configure::read('MISP.default_attribute_distribution');
                    }
                }
                echo $this->Form->input('distribution', array(
                        'options' => $distributionLevels,
                        'label' => __('Distribution ') . $this->element('formInfo', array('type' => 'distribution')),
                        'selected' => $initialDistribution,
                ));
            ?>
        <div id="SGContainer" style="display:none;">
            <?php
                if (!empty($sharingGroups)) {
                    echo $this->Form->input('sharing_group_id', array(
                            'options' => array($sharingGroups),
                            'label' => __('Sharing Group'),
                    ));
                }
            ?>
        </div>
            <?php
                echo $this->Form->input('comment', array(
                        'type' => 'text',
                        'label' => __('Contextual Comment'),
                        'error' => array('escape' => false),
                        'div' => 'input clear',
                        'class' => 'input-xxlarge'
                ));
            //'before' => $this->Html->div('forminfo', isset($attrDescriptions['distribution']['formdesc']) ? $attrDescriptions['distribution']['formdesc'] : $attrDescriptions['distribution']['desc']),));
        ?>
        <div class="input clear"></div>
        <div class="input">
        <?php
            echo $this->Form->input('values.', array(
                'error' => array('escape' => false),
                'type' => 'file',
                'multiple' => true
            ));
        ?>
        </div>
        <div class="input clear"></div>
        <?php
            echo $this->Form->input('malware', array(
                    'type' => 'checkbox',
                    'checked' => false,
                    'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
                    'label' => __('Is a malware sample (encrypt and hash)')
            ));
        ?>
            <div class="input clear"></div>
        <?php
            echo $this->Form->input('advanced', array(
                    'type' => 'checkbox',
                    'checked' => false,
                    'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
                    'label' => __('Advanced extraction (if installed)'),
            ));
        ?>
    </fieldset>
<?php
echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    $event['Event']['id'] = $this->request->data['Attribute']['event_id'];
    $event['Event']['published'] = $published;
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addAttachment', 'event' => $event));
?>
<script type="text/javascript">
<?php
    $formInfoTypes = array('distribution' => 'Distribution', 'category' => 'Category');
    echo 'var formInfoFields = ' . json_encode($formInfoTypes) . PHP_EOL;
    foreach ($formInfoTypes as $formInfoType => $humanisedName) {
        echo 'var ' . $formInfoType . 'FormInfoValues = {' . PHP_EOL;
        foreach ($info[$formInfoType] as $key => $formInfoData) {
            echo '"' . $key . '": "<span class=\"blue bold\">' . h($formInfoData['key']) . '</span>: ' . h($formInfoData['desc']) . '<br />",' . PHP_EOL;
        }
        echo '}' . PHP_EOL;
    }
?>

var formZipTypeValues = new Array();
<?php
    foreach ($categoryDefinitions as $category => $def) {
        $types = $def['types'];
        $alreadySet = false;
        foreach ($types as $type) {
            if (in_array($type, $zippedDefinitions) && !$alreadySet) {
                $alreadySet = true;
                echo "formZipTypeValues['$category'] = \"true\";\n";
            }
        }
        if (!$alreadySet) {
            echo "formZipTypeValues['$category'] = \"false\";\n";
        }
    }
?>

var formAttTypeValues = new Array();
<?php
    foreach ($categoryDefinitions as $category => $def) {
        $types = $def['types'];
        $alreadySet = false;
        foreach ($types as $type) {
            if (in_array($type, $uploadDefinitions) && !$alreadySet) {
                $alreadySet = true;
                echo "formAttTypeValues['$category'] = \"true\";\n";
            }
        }
        if (!$alreadySet) {
            echo "formAttTypeValues['$category'] = \"false\";\n";
        }
    }
?>
$(document).ready(function() {
    initPopoverContent('Attribute');
    $('#AttributeCategory').change(function() {
        malwareCheckboxSetter("Attribute");
    });
    $('#AttributeDistribution').change(function() {
        if ($('#AttributeDistribution').val() == 4) $('#SGContainer').show();
        else $('#SGContainer').hide();
    });

    $("#AttributeCategory, #AttributeDistribution").change(function() {
        initPopoverContent('Attribute');
    });
});

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
