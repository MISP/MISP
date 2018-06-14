<div class="events form">
	<div class="message">
		<?php echo __('The event created will be restricted to %s until it is published.', (Configure::read('MISP.unpublishedprivate') ? __('your organisation only') : __('the organisations included in the distribution setting on the local instance only')));?>
	</div>

<?php echo $this->Form->create('', array('type' => 'file'));?>
	<fieldset>
		<legend><?php echo __('Add Event');?></legend>
		<?php
		echo $this->Form->input('date', array(
				'type' => 'text',
				'class' => 'datepicker'
		));
		$initialDistribution = 3;
		if (Configure::read('MISP.default_event_distribution') != null) {
			$initialDistribution = Configure::read('MISP.default_event_distribution');
		}
		echo $this->Form->input('distribution', array(
				'options' => array($distributionLevels),
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
		echo $this->Form->input('threat_level_id', array(
				'div' => 'input clear',
				'label' => __('Threat Level ') . $this->element('formInfo', array('type' => 'threat_level')),
				'selected' => Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : '4',
				));
		echo $this->Form->input('analysis', array(
				'label' => __('Analysis ') . $this->element('formInfo', array('type' => 'analysis')),
				'options' => array($analysisLevels),
				));
		echo $this->Form->input('info', array(
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
		<?php
		echo $this->Form->input('Event.submittedgfi', array(
				'label' => '<b>GFI sandbox</b>',
				'type' => 'file',
				'div' => 'clear'
				));
		?>
	</fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'add'));
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
	});
</script>
<?php echo $this->Js->writeBuffer();
