<div class="templates form">
<?php
	echo $this->Form->create('Template');
?>
	<fieldset>
		<legend><?php echo __('Edit Template'); ?></legend>
	<?php
		echo ($this->Form->input('name', array('div' => 'clear')));
		echo ($this->Form->input('tags', array('id' => 'hiddenTags','div' => 'clear', 'label' => false, 'type' => 'text', 'value' => '[]', 'style' => 'display:none;')));
		?>
			<div id ="tagList">
				<label>Tags</label>
				<table>
					<tr>
						<td><table><tr id = "tags"></tr></table></td>
						<td id = "addTagButtonTD">
							<span role="button" tabindex="0" aria-label="Add tag" title="Add tag" onClick="activateTagField()" id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;">+</span>
						</td>
						<td id = "addTagFieldTD">
							<?php
								echo $this->Form->input('tagsPusher', array(
									'div' => 'clear',
									'id' => 'addTagField',
									'options' => array($tags),
									'label' => false,
									'onChange' => 'tagFieldChange()',
									'style' => "height:22px;padding:0px;margin-bottom:0px;display:none;",
									'empty' => 'Add a tag',
								));
							?>
						</td>
					</tr>
				</table>
			</div><br />
	<?php
		echo $this->Form->input('description', array(
			'label' => 'Template Description',
			'div' => 'clear',
			'type' => 'textarea',
			'class' => 'form-control span6',
			'placeholder' => 'A description of the template'
		));
		echo $this->Form->input('share', array(
			'label' => 'Share this template with others',
			'type' => 'checkbox'
		));
	?>
	</fieldset>
<?php echo $this->Form->button(__('Edit'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'templates', 'menuItem' => 'edit', 'id' => $id, 'mayModify' => $mayModify));
?>
<script type="text/javascript">
var selectedTags = [
	<?php
		foreach ($currentTags as $k => $t) {
			if ($k != 0) echo ', ';
			echo '"' . $t['Tag']['id'] . '"';
		}
	?>
];
var allTags = [
	<?php
		foreach ($tagInfo as $tag) {
			echo "{'id' : '" . h($tag['Tags']['id']) . "', 'name' : '" . h($tag['Tags']['name']) . "', 'colour' : '" . h($tag['Tags']['colour']) . "'},";
		}
	?>
];
$(document).ready( function () {
	for (var i = 0, len = selectedTags.length; i < len; i++) {
		appendTemplateTag(selectedTags[i], 'yes');
	}
});
</script>
<?php echo $this->Js->writeBuffer();
