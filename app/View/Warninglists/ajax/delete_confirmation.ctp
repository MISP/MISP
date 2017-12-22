<div class="confirmation">
<?php
	echo $this->Form->create('Warninglist', array(
			'style' => 'margin:0px;',
			'id' => 'PromptForm',
			'url' => array('controller' => 'warninglists', 'action' => 'delete', $id)
	));
?>
<legend>Warninglist Deletion</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to delete Warninglist #<?php echo h($id); ?>?<br /> Associated tags will not be removed. You can reload the warninglist at any time by updating your warninglists.</p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<?php
					echo $this->Form->button('Yes', array(
							'type' => 'submit',
							'class' => 'btn btn-primary'
					));
				?>
			</td>
			<td style="width:540px;">
			</td>
			<td style="vertical-align:top;">
				<span role="button" tabindex="0" aria-label="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
			</td>
		</tr>
	</table>
</div>
<?php
	echo $this->Form->end();
?>
</div>
