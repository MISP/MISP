<?php 
$extra = '';
$extra2 = '';
$extra3 = '';
$currentType = 'denyForm';
// 0 = attribute
// 1 = shadow_attribute
if ($object['objectType'] == 0 ) {
	$currentType = 'Attribute';
	if ($object['hasChildren'] == 1) {
		$extra = 'highlight1';
		$extra3 = 'highlightBlueSides highlightBlueTop';
	}
	if (!$mayModify && !$isSiteAdmin) $currentType = 'ShadowAttribute';
} else $extra = 'highlight2';
if ($object['objectType'] == 1) {
	$extra2 = '1';
	$extra3 = 'highlightBlueSides';
	if (isset($object['firstChild'])) {
		$extra3 .= ' highlightBlueTop';
	}
	if (isset($object['lastChild'])) {
		$extra3 .= ' highlightBlueBottom';
	}
}
?>
<tr id = "<?php echo $currentType . '_' . $object['id'] . '_tr'; ?>" class="<? echo $extra3; ?>">
	<?php if ($mayModify): ?>
		<td class="<?php echo $extra; ?>" style="width:10px;">
			<?php if ($object['objectType'] == 0): ?>
			<input id = "select_<?php echo $object['id']; ?>" class="select_attribute" type="checkbox" data-id="<?php echo $object['id'];?>" />
			<?php endif; ?>
		</td>
	<?php endif; ?>
	<td class="short <?php echo $extra; ?>">
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_timestamp_solid'; ?>">
			<?php 
				if (isset($object['timestamp'])) echo date('Y-m-d', $object['timestamp']);
				else echo '&nbsp';				
			?>
		</div>
	</td>
	<td class="shortish <?php echo $extra; ?>">
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_category_placeholder'; ?>" class = "inline-field-placeholder"></div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
			<?php echo h($object['category']); ?>
		</div>
	</td>
	<td class="shortish <?php echo $extra; ?>">
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_placeholder'; ?>" class = "inline-field-placeholder"></div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
			<?php echo h($object['type']); ?>
		</div>
	</td>
	<td class="showspaces <?php echo $extra; ?>">
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class = "inline-field-placeholder"></div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'value', <?php echo $event['Event']['id'];?>);">
			<?php echo nl2br(h($object['value'])); ?>
		</div>
	</td>
	<td class="showspaces bitwider <?php echo $extra; ?>">
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_placeholder'; ?>" class = "inline-field-placeholder"></div>
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
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_placeholder'; ?>" class = "inline-field-placeholder"></div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'to_ids', <?php echo $event['Event']['id'];?>);">
			<?php 
				if ($object['to_ids']) echo 'Yes';
				else echo 'No';
			?>
		</div>
	</td>
	<td class="<?php echo $extra; ?>" style="width:150px;">
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_placeholder'; ?>" class = "inline-field-placeholder"></div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
			<?php if ($object['objectType'] != 1 && $object['objectType'] != 2) echo h($distributionLevels[$object['distribution']]); ?>&nbsp;
		</div>
	</td>
	<td class="short action-links <?php echo $extra;?>">
		<?php
			if ($object['objectType'] == 0) {
				if ($isSiteAdmin || $mayModify) {
					echo $this->Form->create('Attribute', array('class' => 'inline-delete', 'id' => $currentType . '_' . $object['id'] . '_delete', 'action' => 'delete'));
		?>
			<a href="/attributes/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit useCursorPointer"></a>
			<span class="icon-trash useCursorPointer" onClick="deleteObject('attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
		<?php 
					echo $this->Form->end();					
				} else {
					echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'edit', $object['id']), array('class' => 'icon-edit', 'title' => 'Propose Edit'));
				}
			} else {
				if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin) {
					echo $this->Form->create('ShadowAttribute', array('class' => 'inline-delete', 'style' => 'display:inline-block;', 'id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'action' => 'accept'));
				?>
					<span class="icon-ok useCursorPointer" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
				<?php 
					echo $this->Form->end();
					//echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'accept', $object['id']), array('class' => 'icon-ok', 'title' => 'Accept'), 'Are you sure you want to accept this proposal?');
				}
				if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin || ($object['org'] == $me['org'])) {
					echo $this->Form->create('ShadowAttribute', array('class' => 'inline-delete', 'style' => 'display:inline-block;', 'id' => 'ShadowAttribute_' . $object['id'] . '_delete', 'action' => 'delete'));
				?>
					<span class="icon-trash useCursorPointer" onClick="deleteObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
				<?php 
					echo $this->Form->end();
				}
			}
		?>
	</td>
</tr>	