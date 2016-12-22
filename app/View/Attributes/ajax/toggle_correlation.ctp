<div class="confirmation">
	<?php
	echo $this->Form->create('Attribute', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/attributes/toggleCorrelation/' . $attribute['Attribute']['id']));
	$extraTitle = "";
	?>
	<legend>Toggle Correlation <?php echo $attribute['Attribute']['disable_correlation'] ? 'on' : 'off'?></legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<p>
    <?php
      if ($attribute['Attribute']['disable_correlation']) {
        echo 'Re-enable the correlation for this attribute.';
      } else {
        echo 'This will remove all correlations that already exist for this attribute and prevents any attributes to be related as long as this setting is disabled. Make sure you understand the downasides of disabling correlations.';
      }
    ?>
    </p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span id="PromptYesButton" class="btn btn-primary" onClick="submitPublish();">Yes</span>
				</td>
				<td style="width:540px;">
				</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
				</td>
			</tr>
		</table>
	</div>
	<?php
		echo $this->Form->end();
	?>
</div>
