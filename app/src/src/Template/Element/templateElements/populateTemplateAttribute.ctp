<div id="element_<?php echo $k; ?>">
	<div class="populate_template_div_body">
		<div class="left-inverse">Field:</div>
		<div class="right-inverse">
			<?php echo h($element['name']); ?>
			<?php if ($element['mandatory']): ?>
				<span class="template_mandatory">(*)</span>
			<?php endif;?>
		</div><br />
		<div class="left">Description:</div>
		<div class="right"><?php echo h($element['description']); ?></div><br />

		<div class="left">Type<?php if ($element['complex']) echo 's'; ?>:</div>
		<div class="right">
		<?php
			$types = '';
			if ($element['complex']) {
				foreach ($validTypeGroups[$element['type']]['types'] as $k => $type):
					if ($k != 0) $types .= ', ';
					$types .= $type;
					?>
						<div class="templateTypeBox"><?php echo h($type); ?></div>
					<?php
				endforeach;
			} else {
				?>
					<div class="templateTypeBox"><?php echo h($element['type']); ?></div>
				<?php
			}
		?>
		</div>
		<div>
		<?php
			if (isset($template['Template']['value_' . $element_id])) $value = $template['Template']['value_' . $element_id];
			if (isset($errors[$element_id])) $error = $errors[$element_id];
			if ($element['batch']) {
				if ($element['complex']) {
					$placeholder = 'Describe the ' . h($element['name']) . ' using one or several (separated by a line-break) of the following types: ' . $types;
				} else {
					$placeholder = 'Describe the ' . h($element['name']) . ' using one or several ' . h($element['type']) . 's (separated by a line-break)';
				}
				echo $this->Form->input('value_' . $element_id, array(
					'type' => 'textarea',
					'label' => false,
					'div' => false,
					'style' => 'width: calc(100% - 16px);',
					'placeholder' => $placeholder,
					'value' => $value,
				));
			} else {
				if ($element['complex']) {
					$placeholder = 'Describe the ' . h($element['name']) . ' using one of the following types: ' . $types;
				} else {
					$placeholder = 'Describe the ' . h($element['name']) . ' using a ' . h($element['type']);
				}
				echo $this->Form->input('value_' . $element_id, array(
					'type' => 'text',
					'label' => false,
					'div' => false,
					'style' => 'width: calc(100% - 16px);',
					'placeholder' => $placeholder,
					'value' => $value,
				));
			}
		?>
		</div>
		<div class="error-message populateTemplateErrorField" <?php if (!isset($errors[$element_id])) echo 'style="display:none;"';?>>
			<?php echo 'Error: ' . $errors[$element_id]; ?>
		</div>
	</div>
</div>
