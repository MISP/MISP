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
	if (!$mayModify) $currentType = 'ShadowAttribute';
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
<tr id = "<?php echo $currentType . '_' . $object['id'] . '_tr'; ?>" class="<?php echo $extra3; ?>">
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
		<?php if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ): ?>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid">
		<?php else: ?>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'value', <?php echo $event['Event']['id'];?>);">
			<?php 
			endif;
				$sigDisplay = $object['value'];
				if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ) {
					$t = ($currentType == 'Attribute' ? 'attributes' : 'shadow_attributes');
					$filenameHash = explode('|', nl2br(h($object['value'])));
					if (strrpos($filenameHash[0], '\\')) {
						$filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
						$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
						echo h($filepath);
						echo $this->Html->link($filename, array('controller' => $t, 'action' => 'download', $object['id']));
					} else {
						echo $this->Html->link($filenameHash[0], array('controller' => $t, 'action' => 'download', $object['id']));
					}
					if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
				} elseif (strpos($object['type'], '|') !== false) {
					$filenameHash = explode('|', $object['value']);
					echo h($filenameHash[0]);
					if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
				} elseif ('vulnerability' == $object['type']) {
					if (! is_null(Configure::read('MISP.cveurl'))) {
						$cveUrl = Configure::read('MISP.cveurl');
					} else {
						$cveUrl = "http://www.google.com/search?q=";
					}
					echo $this->Html->link(h($sigDisplay), h($cveUrl) . h($sigDisplay), array('target' => '_blank'));
				} elseif ('link' == $object['type']) {
					echo $this->Html->link(h($sigDisplay), h($sigDisplay));
				} else {
					$sigDisplay = str_replace("\r", '', $sigDisplay);
					echo nl2br(h($sigDisplay));
				}
			?>
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
	<td class="<?php echo $extra; ?> shortish">
		<?php 
			$turnRed = '';
			if ($object['objectType'] == 0 && $object['distribution'] == 0) $turnRed = 'style="color:red"';
		?>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_placeholder'; ?>" class = "inline-field-placeholder"></div>
		<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" <?php echo $turnRed; ?> class="inline-field-solid" onClick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
			<?php if ($object['objectType'] == 0) echo h($distributionLevels[$object['distribution']]); ?>&nbsp;
		</div>
	</td>
	<td class="short action-links <?php echo $extra;?>">
		<?php
			if ($object['objectType'] == 0) {
				if ($isSiteAdmin || $mayModify) {
		?>
			<a href="<?php echo $baseurl."/attributes/edit/".$object['id']; ?>" title="Edit" class="icon-edit useCursorPointer"></a>
			<span class="icon-trash useCursorPointer" onClick="deleteObject('attributes', 'delete', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
		<?php 			
				} else {
		?>
					<a href="<?php echo $baseurl."/shadow_attributes/edit/".$object['id']; ?>" title="Propose Edit" class="icon-edit useCursorPointer"></a>
		<?php 
				}
			} else {
				if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin) {
				?>
					<span class="icon-ok useCursorPointer" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
				<?php 
				}
				if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin || ($object['org'] == $me['org'])) {
				?>
					<span class="icon-trash useCursorPointer" onClick="deleteObject('shadow_attributes', 'discard' ,'<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
				<?php 
				}
			}
		?>
	</td>
</tr>	