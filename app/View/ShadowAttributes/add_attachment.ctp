<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");'));?>
    <fieldset>
            <legend><?php echo __('Propose Attachment'); ?></legend>
    <?php
        echo $this->Form->hidden('event_id');
        echo $this->Form->input('category', array(
            'default' => 'Payload delivery',
            'label' => __('Category ') . $this->element('formInfo', array('type' => 'category'))
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
        ));
    ?>
    </fieldset>
<?php
    echo $this->Form->button(__('Propose'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    $event['Event']['id'] = $this->request->data['ShadowAttribute']['event_id'];
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttachment', 'event' => $event));
?>

<script type="text/javascript">
<?php
    $formInfoTypes = array('category' => 'Category');
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

$(document).ready(function() {
    initPopoverContent('ShadowAttribute');
    $('#ShadowAttributeCategory').change(function() {
        malwareCheckboxSetter('ShadowAttribute');
    });
});

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
