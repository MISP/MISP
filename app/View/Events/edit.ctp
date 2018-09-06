<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
$mayPublish = ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id']);
?>
<div class="events form">
<?php echo $this->Form->create('Event');?>
    <fieldset>
        <legend><?php echo __('Edit Event');?></legend>
<?php
    echo $this->Form->input('id');
    echo $this->Form->input('date', array(
            'type' => 'text',
            'class' => 'datepicker'
    ));
    echo $this->Form->input('distribution', array(
        'options' => array($distributionLevels),
        'label' => 'Distribution ' . $this->element('formInfo', array('type' => 'distribution')),
        'default' => $event['Event']['distribution'],
    ));
?>
    <div id="SGContainer" style="display:none;">
        <?php
        if (!empty($sharingGroups)) {
            echo $this->Form->input('sharing_group_id', array(
                'options' => array($sharingGroups),
                'label' => __('Sharing Group'),
                'default' => $event['Event']['sharing_group_id'],
            ));
        }
        ?>
    </div>
<?php
    echo $this->Form->input('threat_level_id', array(
            'div' => 'input clear',
            'label' => __('Threat Level ') . $this->element('formInfo', array('type' => 'threat_level'))
    ));
    echo $this->Form->input('analysis', array(
            'label' => __('Analysis ') . $this->element('formInfo', array('type' => 'analysis')),
            'options' => array($analysisLevels)
    ));
    echo $this->Form->input('info', array(
            'div' => 'clear',
            'label' => __('Event Info'),
            'div' => 'clear',
            'type' => 'text',
            'class' => 'form-control span6',
            'placeholder' => __('Quick Event Description or Tracking Info')
    ));
    echo $this->Form->input('extends_uuid', array(
            'label' => __('Extends event'),
            'div' => 'clear',
            'class' => 'form-control span6',
            'placeholder' => __('Event UUID or ID. Leave blank if not applicable.')
    ));
?>
        <div id="extended_event_preview" style="width:446px;"></div>
    </fieldset>
<?php
echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'editEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>

<script type="text/javascript">
    <?php
        $formInfoTypes = array('distribution' => 'Distribution', 'analysis' => 'Analysis', 'threat_level' => 'ThreatLevelId');
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
        if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
        else $('#SGContainer').hide();

        $('#EventDistribution').change(function() {
            if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
            else $('#SGContainer').hide();
        });

        $("#EventDistribution, #EventAnalysis, #EventThreatLevelId").change(function() {
            initPopoverContent('Event');
        });

        $("#EventExtendsUuid").keyup(function() {
            previewEventBasedOnUuids();
        });

        $(document).ready(function() {
            if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
            else $('#SGContainer').hide();
            initPopoverContent('Event');
            previewEventBasedOnUuids();
        });
    });
</script>
<?php echo $this->Js->writeBuffer();
