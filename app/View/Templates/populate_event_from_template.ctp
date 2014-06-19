<div class="populate_from_template form">
<?php echo $this->Form->create('', array('type' => 'file'));?>
	<fieldset>
		<div id="populate_template_info" class="templateTableRow templateTableRow80">
			<?php 
				echo $this->element('templateElements/populateTemplateDescription');
			?>
		</div>
		<?php 
			foreach ($templateData['TemplateElement'] as $k => $element) {
				echo $this->element('templateElements/populateTemplate' . ucfirst($element['element_definition']), array('element' => $element['TemplateElement' . ucfirst($element['element_definition'])][0], 'k' => $k, 'element_id' => $element['id'], 'value' => ''));
			}
		?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
