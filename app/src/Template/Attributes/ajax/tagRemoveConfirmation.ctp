<div class="confirmation">
	<?php
	echo $this->Form->create($model, array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/' . strtolower($model) . 's/removeTag/' . $id . '/' . $tag_id));
	$action = "removeObjectTag('" . $model . "', '" . h($id) . "', '" . h($tag_id) . "');";
	?>
	<legend>Remove Tag</legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
	<p>Remove tag (<?php echo h($tag_id); ?>) from <?php echo ucfirst(h($model)); ?> (<?php echo h($id); ?>)?</p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span id="PromptYesButton" class="btn btn-primary" title="Remove" role="button" tabindex="0" aria-label="Remove" onClick="<?php echo $action; ?>">Yes</span>
				</td>
				<td style="width:540px;">
				</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" id="PromptNoButton" title="Cancel" role="button" tabindex="0" aria-label="Cancel" onClick="cancelPrompt();">No</span>
				</td>
			</tr>
		</table>
	</div>
	<?php
		echo $this->Form->end();
	?>
</div>
