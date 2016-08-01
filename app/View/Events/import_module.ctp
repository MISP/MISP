<div class="events form">
<?php echo $this->Form->create('', array('type' => 'file'));?>
	<fieldset>
		<legend><?php echo h(Inflector::humanize($module['name']));?></legend>
		<?php
			if (isset($module['mispattributes']['userConfig']) && !empty($module['mispattributes']['userConfig'])) {
				foreach ($module['mispattributes']['userConfig'] as $configName => $config) {
					?>
						<p>
							<span class="bold">
								<?php
									echo ucfirst(h($configName));
								?>
							</span><br />
							<?php 
								if (isset($config['message']) && !empty($config['message'])) {
									echo PHP_EOL . h($config['message']);
								}
							?>
						</p>
					<?php
					$settings = array(
						'label' => false,
						'div' => false
					);
					if (isset($configTypes[$config['type']]['class'])) {
						$settings['class'] = $configTypes[$config['type']]['class'];
					}
					if (isset($configTypes[$config['type']]['type'])) {
						$settings['type'] = $configTypes[$config['type']]['type'];
					}
					echo $this->Form->input('Event.config.' . $configName, $settings);
					?>
						<div class="input clear"></div><br />
					<?php 
				}
			}
			$source = 'paste';
			if (in_array('paste', $module['mispattributes']['inputSource']) && in_array('file', $module['mispattributes']['inputSource'])) {
				$source = 'both';
			} else if (in_array('file', $module['mispattributes']['inputSource'])) {
				$source = 'file';
			}
			?>

			<?php 
			echo $this->Form->input('Event.source', array(
				'label' => false,
				'checked' => $source == 'file' ? true : false,
				'disabled' => $source == 'both' ? false : true,
				'div' => false,
				'style' => 'margin-bottom:5px;'
			));
			?>
			<span class="bold" style="margin-top:5px;">
				File upload
			</span>
				<div class="input clear"></div>
				<div id="pasteDiv">
				<p class="bold">
					Paste Input
				</p>
			<?php 
					if (in_array('paste', $module['mispattributes']['inputSource'])) {
						echo $this->Form->input('Event.paste', array(
							'label' => false,
							'type' => 'textarea',
							'class' => 'input-xxlarge',
							'rows' => 12,
							'div' => false
						));
					}
			?>
				</div>
				<div class="input clear"></div>
				<div id="fileDiv">
				<p class="bold">
					Input File
				</p>
			<?php 
					if (in_array('file', $module['mispattributes']['inputSource'])) {
						echo $this->Form->input('Event.fileupload', array(
								'label' => false,
								'type' => 'file',
								'div' => 'clear'
						));
					}
			?>
				</div>
				<div class="input clear"></div>
	</fieldset>
<?php
echo $this->Form->button('Import', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>

<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'import'));
?>
<script type="text/javascript">
$(document).ready(function() {
	changeImportSource();
	$('#EventSource').change(function() {
		changeImportSource();
	});
});


function changeImportSource() {
	if ($('#EventSource').is(':checked')) {
		$('#fileDiv').show();
		$('#pasteDiv').hide();
	} else {
		$('#fileDiv').hide();
		$('#pasteDiv').show();
	};
}
</script>
