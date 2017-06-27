<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
$mayPublish = ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id']);
?>
<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend>Edit Event</legend>
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
				'label' => 'Sharing Group',
				'default' => $event['Event']['sharing_group_id'],
			));
		}
		?>
	</div>
<?php
	echo $this->Form->input('threat_level_id', array(
			'div' => 'input clear',
			'label' => 'Threat Level ' . $this->element('formInfo', array('type' => 'threat_level'))
	));
	echo $this->Form->input('analysis', array(
			'label' => 'Analysis ' . $this->element('formInfo', array('type' => 'analysis')),
			'options' => array($analysisLevels)
	));
	echo $this->Form->input('info', array(
			'div' => 'clear',
			'label' => 'Event Info',
			'div' => 'clear',
			'type' => 'text',
			'class' => 'form-control span6',
			'placeholder' => 'Quick Event Description or Tracking Info'
	));

?>
	</fieldset>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
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

		$(document).ready(function() {
			if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
			else $('#SGContainer').hide();
			initPopoverContent('Event');
		});
	});
</script>
<?php echo $this->Js->writeBuffer();
