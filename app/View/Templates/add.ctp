<div class="templates form">
<?php
	echo $this->Form->create('Template');
?>
	<fieldset>
		<legend><?php echo __('Create Template'); ?></legend>
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
							<button onClick="activateTagField()" id="addTagButton" title="Add tag" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;">+</button>
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
<?php echo $this->Form->button(__('Create'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'templates', 'menuItem' => 'add'));
?>
<script type="text/javascript">
var selectedTags = [];
var allTags = [
	<?php
		foreach ($tagInfo as $tag) {
			echo "{'id' : '" . h($tag['Tags']['id']) . "', 'name' : '" . h($tag['Tags']['name']) . "', 'colour' : '" . h($tag['Tags']['colour']) . "'},";
		}
	?>
];
</script>
<?php echo $this->Js->writeBuffer();
