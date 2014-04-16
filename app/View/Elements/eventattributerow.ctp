<?php 
$extra = '';
$extra2 = '';
$currentType = 'ShadowAttribute';
// 0 = attribute
// 1 = shadow_attribute
if ($object['objectType'] == 0 ) {
	$currentType = 'Attribute';
	if ($object['hasChildren'] == 1) $extra = 'highlight1';
} else $extra = 'highlight2';
if ($object['objectType'] == 1) $extra2 = '1';
?>
<tr id = "<?php echo $currentType . '_' . $object['id'] . '_tr'; ?>">
	<?php if ($mayModify): ?>
		<td class="<?php echo $extra; ?>" style="width:10px;">
			<?php if ($object['objectType'] == 0): ?>
			<input id = "select_<?php echo $object['id']; ?>" class="select_attribute" type="checkbox" data-id="<?php echo $object['id'];?>" />
			<?php endif; ?>
		</td>
	<?php endif; ?>
	<td class="short <?php echo $extra; ?>">
	<?php 
		if (isset($object['timestamp'])) echo date('Y-m-d', $object['timestamp']);
		else echo '&nbsp';				
	?>
	</td>
	<td class="shortish <?php echo $extra; ?>">
		<?php 
			echo $this->Form->create($currentType, array('class' => 'inline-form inline-field-form', 'id' => $currentType . '_' . $object['id'] . '_category_form', 'action' => 'editField'));
		?>
		<div class='inline-input inline-input-container'>	
		<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
		<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>	
		<?php 
			echo $this->Form->input('category', array(
				'options' => array(array_combine($typeCategory[$object['type']], $typeCategory[$object['type']])),
				'label' => false,
				'selected' => $object['category'],
				'error' => array('escape' => false),
				'class' => 'inline-input',
				'id' => $currentType . '_' . $object['id'] . '_category_field',
				'div' => false
			));
			echo $this->Form->end();
		?>
		</div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
			<?php echo h($object['category']); ?>
		</div>
	</td>
	<td class="shortish <?php echo $extra; ?>">
		<?php 
			echo $this->Form->create($currentType, array('class' => 'inline-form inline-field-form', 'id' => $currentType . '_' . $object['id'] . '_type_form', 'action' => 'editField'));
		?>
		<div class='inline-input inline-input-container'>	
			<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
			<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>	
		<?php 
			echo $this->Form->input('type', array(
				'options' => array(array_combine($categoryDefinitions[$object['category']]['types'], $categoryDefinitions[$object['category']]['types'])),
				'label' => false,
				'selected' => $object['type'],
				'error' => array('escape' => false),
				'class' => 'inline-input',
				'id' => $currentType . '_' . $object['id'] . '_type_field',
				'div' => false
			));
			echo $this->Form->end();
		?>
		</div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
			<?php echo h($object['type']); ?>
		</div>
	</td>
	<td class="showspaces <?php echo $extra; ?>">
		<?php 
			echo $this->Form->create($currentType, array('class' => 'inline-form inline-field-form', 'id' => $currentType . '_' . $object['id'] . '_value_form', 'action' => 'editField', 'default' => false));
		?>
			<div class='inline-input inline-input-container'>	
			<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
			<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>	
		<?php 
			echo $this->Form->input('value', array(
					'type' => 'textarea',
					'label' => false,
					'value' => h($object['value']),
					'error' => array('escape' => false),
					'class' => 'inline-input',
					'id' => $currentType . '_' . $object['id'] . '_value_field',
					'div' => false
			));
		?>
			</div>
		<?php 
			echo $this->Form->end();
		?>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'value', <?php echo $event['Event']['id'];?>);">
			<?php echo nl2br(h($object['value'])); ?>
		</div>
	</td>
	<td class="showspaces bitwider <?php echo $extra; ?>">
		<?php 
			echo $this->Form->create($currentType, array('class' => 'inline-form inline-field-form', 'id' => $currentType . '_' . $object['id'] . '_comment_form', 'action' => 'editField'));
		?>
			<div class='inline-input inline-input-container'>	
			<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
			<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>	
		<?php 	
			echo $this->Form->input('comment', array(
					'type' => 'textarea',
					'label' => false,
					'value' => h($object['comment']),
					'error' => array('escape' => false),
					'class' => 'inline-input',
					'id' => $currentType . '_' . $object['id'] . '_comment_field',
					'div' => false
			));
			echo $this->Form->end();
		?>
		</div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
			<?php echo nl2br(h($object['comment'])); ?>&nbsp;
		</div>
	</td>
	<td class="shortish <?php echo $extra; ?>">
		<ul class="inline" style="margin:0px;">
			<?php 
				if ($object['objectType'] == 0 && isset($relatedAttributes[$object['id']]) && (null != $relatedAttributes[$object['id']])) {
					foreach ($relatedAttributes[$object['id']] as $relatedAttribute) {
						echo '<li style="padding-right: 0px; padding-left:0px;" title ="' . h($relatedAttribute['info']) . '"><span>';
						if ($relatedAttribute['org'] == $me['org']) {
							echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']), array ('style' => 'color:red;'));
						} else {
							echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']));
						}
	
						echo "</span></li>";
						echo ' ';
					}
				}
			?>
		</ul>
	</td>
	<td class="short <?php echo $extra; ?>">
		<?php 
			echo $this->Form->create($currentType, array('class' => 'inline-form inline-field-form', 'id' => $currentType . '_' . $object['id'] . '_ids_form', 'action' => 'editField'));
		?>
			<div class='inline-input inline-input-container'>	
			<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
			<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>
		<?php 	
			$current = 0;
			if ($object['to_ids']) $current = 1;
			echo $this->Form->input('to_ids', array(
					'options' => array(0 => 'No', 1 => 'Yes'),
					'label' => false,
					'selected' => $current,
					'class' => 'inline-input',
					'id' => $currentType . '_' . $object['id'] . '_ids_field',
					'div' => false
			));
			echo $this->Form->end();
		?>
		</div>	
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_ids_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'ids', <?php echo $event['Event']['id'];?>);">
			<?php 
				if ($object['to_ids']) echo 'Yes';
				else echo 'No';
			?>
		</div>
	</td>
	<td class="<?php echo $extra; ?>" style="width:150px;">
		<?php 
			echo $this->Form->create($currentType, array('class' => 'inline-form inline-field-form', 'id' => $currentType . '_' . $object['id'] . '_distribution_form', 'action' => 'editField'));
		?>
		<div class='inline-input inline-input-container'>	
			<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
			<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>	
			<?php 
				echo $this->Form->input('distribution', array(
						'options' => array($distributionLevels),
						'label' => false,
						'selected' => $object['distribution'],
						'error' => array('escape' => false),
						'class' => 'inline-input',
						'id' => $currentType . '_' . $object['id'] . '_distribution_field',
						'div' => false
				));
				echo $this->Form->end();
			?>		
		</div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
			<?php if ($object['objectType'] != 1 && $object['objectType'] != 2) echo h($distributionLevels[$object['distribution']]); ?>&nbsp;
		</div>
	</td>
	<td class="short action-links <?php echo $extra;?>">
		<?php
			if ($object['objectType'] == 0) {
				if ($isSiteAdmin || $mayModify) {
					echo $this->Form->create('Attribute', array('class' => 'inline-delete', 'id' => $currentType . '_' . $object['id'] . '_delete', 'action' => 'delete'));
					echo $this->Form->end();
		?>
			<a href="/attributes/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit"></a>
			<span id = "<?php echo $currentType . '_' . $object['id'] . '_delete'; ?>" class="icon-trash" onClick="deleteObject('attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
		<?php 
					echo $this->Form->end();					
				} else {
					echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'edit', $object['id']), array('class' => 'icon-edit', 'title' => 'Propose Edit'));
				}
			} else {
				if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin) {
					echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'accept', $object['id']), array('class' => 'icon-ok', 'title' => 'Accept'), 'Are you sure you want to accept this proposal?');
				}
				if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin || ($object['org'] == $me['org'])) {
					echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'discard', $object['id']), array('class' => 'icon-trash', 'title' => 'Discard'), 'Are you sure you want to discard this proposal?');
				}
			}
		?>
	</td>
</tr>	