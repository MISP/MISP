<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("AttributeMalware").removeAttribute("disabled");'));?>
    <fieldset>
        <legend><?php echo __('Add Attachment(s)'); ?></legend>
        <?php
            $categoryFormInfo = $this->element('genericElements/Form/formInfo', [
                'field' => [
                    'field' => 'category'
                ],
                'modelForForm' => 'Attribute',
                'fieldDesc' => $fieldDesc['category'],
            ]);
            echo $this->Form->hidden('event_id');
            echo $this->Form->input('category', array(
                'default' => 'Payload delivery',
                'label' => __('Category ') . $categoryFormInfo
            ));
        ?>
        <div class='input clear'></div>
        <?php
            $distributionFormInfo = $this->element('genericElements/Form/formInfo', [
                'field' => [
                    'field' => 'distribution'
                ],
                'modelForForm' => 'Attribute',
                'fieldDesc' => $fieldDesc['distribution'],
            ]);
            echo $this->Form->input('distribution', array(
                'options' => $distributionLevels,
                'label' => __('Distribution ') . $distributionFormInfo,
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
                    'checked' => true,
                    'label' => __('Is a malware sample (encrypt and hash)')
            ));
        ?>
            <div class="input clear"></div>
        <?php
            $maliciousOptions = array();
            foreach ($attachmentObjectTemplates['malicious'] as $tpl) {
                $maliciousOptions[$tpl['uuid']] = $tpl['label'];
            }
            $maliciousDefault = array_key_first($maliciousOptions);

            $nonMaliciousOptions = array();
            foreach ($attachmentObjectTemplates['non_malicious'] as $tpl) {
                $key = $tpl['uuid'] === null ? '' : $tpl['uuid'];
                $nonMaliciousOptions[$key] = $tpl['label'];
            }
            $nonMaliciousDefault = array_key_first($nonMaliciousOptions);
        ?>
        <div id="MaliciousObjectTemplateContainer" class="input clear">
            <?php
                echo $this->Form->input('object_template_malicious', array(
                    'type' => 'select',
                    'options' => $maliciousOptions,
                    'empty' => false,
                    'selected' => $maliciousDefault,
                    'label' => __('Object template'),
                ));
            ?>
        </div>
        <div id="NonMaliciousObjectTemplateContainer" class="input clear" style="display:none;">
            <?php
                echo $this->Form->input('object_template_non_malicious', array(
                    'type' => 'select',
                    'options' => $nonMaliciousOptions,
                    'empty' => false,
                    'selected' => $nonMaliciousDefault,
                    'label' => __('Object template'),
                ));
            ?>
        </div>
        <div class="input clear"></div>
        <?php
            echo $this->Form->input('advanced', array(
                    'type' => 'checkbox',
                    'checked' => false,
                    'disabled' => !$advancedExtractionAvailable,
                    'data-disabled-reason' => !$advancedExtractionAvailable ? __('Advanced extraction is not installed') : '',
                    'div' => array('id' => 'advanced_input', 'style' => 'display:none'),
                    'label' => __('Advanced extraction'),
            ));
        ?>
    </fieldset>
<?php
echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'addAttachment', 'event' => $event)); ?>
<script>
var formZipTypeValues = <?= json_encode($isMalwareSampleCategory) ?>;
var fileTemplateUuid = <?= json_encode($maliciousDefault) ?>;

$(function() {
    function updateAdvancedVisibility() {
        var malwareChecked = $("#AttributeMalware").is(':checked');
        var isFileTemplate = $('#AttributeObjectTemplateMalicious').val() === fileTemplateUuid;
        if (malwareChecked && isFileTemplate) {
            $('#advanced_input').show();
        } else {
            $('#advanced_input').hide();
        }
    }

    $('#AttributeCategory').change(function() {
        malwareCheckboxSetter("Attribute");
        $("#AttributeMalware").change();
    });

    $('#AttributeDistribution').change(function() {
        if ($(this).val() == 4) {
            $('#SGContainer').show();
        } else {
            $('#SGContainer').hide();
        }
    }).change();

    $("#AttributeMalware").change(function () {
        if (this.checked) {
            $('#MaliciousObjectTemplateContainer').show();
            $('#NonMaliciousObjectTemplateContainer').hide();
        } else {
            $('#MaliciousObjectTemplateContainer').hide();
            $('#NonMaliciousObjectTemplateContainer').show();
        }
        updateAdvancedVisibility();
    }).change();

    $('#AttributeObjectTemplateMalicious').change(updateAdvancedVisibility);
});
</script>
