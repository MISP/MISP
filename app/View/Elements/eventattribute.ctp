<?php
	$mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc'] == $me['org']) || ($isAclModifyOrg && $event['Event']['orgc'] == $me['org']));
	$mayPublish = ($isAclPublish && $event['Event']['orgc'] == $me['org']);
	$pageCount = intval($objectCount / 50);
	if ($objectCount%50 != 0) $pageCount++;
	$possibleAction = 'Proposal';
	if ($mayModify) $possibleAction = 'Attribute';
	if ($pageCount > 1):
		$startRecord = 1;
		$endRecord = $objectCount;
		if ($page != 'all') {
			$startRecord = (($page-1) * 50) + 1;
			$endRecord = (($page-1) * 50) + count($eventArray);
		}
?>
<div class="pagination">
	<ul>
		<?php if ($page == 1) : ?>
			<li class="prev"><span>« previous</span></li>
		<?php else: ?>
			<li class="prev"><a href="" id = "aprev" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', <?php echo $page-1; ?>);return false;">« previous</a></li>
		<?php endif; 
		for ($i = 1; $i < (1+$pageCount); $i++): 
			if ($page != $i):
		?>
				<li><a href="" id = "apage<?php echo $i; ?>" data-page-value="<?php echo $i; ?>" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', <?php echo $i; ?>);return false;"><?php echo $i; ?></a></li>
		<?php
			else:
		?>
				<li><span id = "apageCurrent" class = "red bold"><?php echo $i; ?></span></li>
		<?php 
			endif;
		endfor;
		if ($page >= $pageCount): ?>
			<li class="next"><span>next »</span></li>
		<?php else: ?>
			<li class="next"><a href="" id = "anext" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', <?php echo $page+1; ?>);return false;">next »</a></li>
		<?php endif; 
		if ($page == 'all'): ?>
			<li class="all red bold"><span>View All</span></li>
		<?php else: ?>
			<li class="all"><a href="" id = "aall" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', 'all');return false;">View All</a></li>
		<?php endif; ?>
	</ul>
</div>
<br />
<?php 
	endif;
?>
<div id="edit_object_div">
	<?php 
		echo $this->Form->create('Attribute', array('id' => 'delete_selected', 'url' => '/attributes/deleteSelected/' . $event['Event']['id']));
		echo $this->Form->input('ids_delete', array(
			'type' => 'text',
			'value' => 'test',
			'style' => 'display:none;',
			'label' => false,
		)); 
		echo $this->Form->end();
	?>
		<?php 
		echo $this->Form->create('ShadowAttribute', array('id' => 'accept_selected', 'url' => '/shadow_attributes/acceptSelected/' . $event['Event']['id']));
		echo $this->Form->input('ids_accept', array(
			'type' => 'text',
			'value' => '',
			'style' => 'display:none;',
			'label' => false,
		)); 
		echo $this->Form->end();
	?>
		<?php 
		echo $this->Form->create('ShadowAttribute', array('id' => 'discard_selected', 'url' => '/shadow_attributes/discardSelected/' . $event['Event']['id']));
		echo $this->Form->input('ids_discard', array(
			'type' => 'text',
			'value' => '',
			'style' => 'display:none;',
			'label' => false,
		)); 
		echo $this->Form->end();
	?>
</div>
<div id="attributeList" class="attributeListContainer">
	<div class="tabMenu tabMenuEditBlock noPrint">
		<span id="create-button" title="Add attribute" class="icon-plus useCursorPointer" onClick="clickCreateButton(<?php echo $event['Event']['id']; ?>, '<?php echo $possibleAction; ?>');"></span>
		<span id="multi-edit-button" title="Edit selected Attributes" class="icon-edit mass-select useCursorPointer" onClick="editSelectedAttributes(<?php echo $event['Event']['id']; ?>);"></span>
		<span id="multi-delete-button" title="Delete selected Attributes" class = "icon-trash mass-select useCursorPointer" onClick="multiSelectAction(<?php echo $event['Event']['id']; ?>, 'deleteAttributes');"></span>
		<span id="multi-accept-button" title="Accept selected Proposals" class="icon-ok mass-proposal-select useCursorPointer" onClick="multiSelectAction(<?php echo $event['Event']['id']; ?>, 'acceptProposals');"></span>
		<span id="multi-discard-button" title="Discard selected Proposals" class = "icon-remove mass-proposal-select useCursorPointer" onClick="multiSelectAction(<?php echo $event['Event']['id']; ?>, 'discardProposals');"></span>
	</div>
	<?php if ($mayModify): ?>
	<div class="tabMenu tabMenuToolsBlock noPrint">
		<span id="create-button" title="Populate using a template" class="icon-list-alt useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'templates', 'templateChoices');"></span>
		<span id="freetext-button" title="Populate using the freetext import tool" class="icon-exclamation-sign useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'events', 'freeTextImport');"></span>
		<span id="attribute-replace-button" title="Replace all attributes of a category/type combination within the event" class="icon-random useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'attributes', 'attributeReplace');"></span>	
	</div>
	<?php endif; ?>
	<table class="table table-striped table-condensed">
		<tr>
			<?php if ($mayModify && !empty($eventArray)): ?>
				<th><input class="select_all" type="checkbox" onClick="toggleAllAttributeCheckboxes();" /></th>
			<?php endif;?>
			<th>Date</th>
			<th>Category</th>
			<th>Type</th>
			<th>Value</th>
			<th>Comment</th>
			<th>Related Events</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>">IDS</th>
			<th title="<?php echo $attrDescriptions['distribution']['desc'];?>">Distribution</th>
			<th class="actions">Actions</th>
		</tr>
		<?php 
			foreach($eventArray as $k => $object):
				$extra = '';
				$extra2 = '';
				$extra3 = '';
				$currentType = 'denyForm';
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
							<?php else: ?>
								<input id = "select_proposal_<?php echo $object['id']; ?>" class="select_proposal" type="checkbox" data-id="<?php echo $object['id'];?>" />
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
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
							<?php echo h($object['category']); ?>
						</div>
					</td>
					<td class="shortish <?php echo $extra; ?>">
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_placeholder'; ?>" class = "inline-field-placeholder"></div>
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
							<?php echo h($object['type']); ?>
						</div>
					</td>
					<td class="showspaces <?php echo $extra; ?> limitedWidth">
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class = "inline-field-placeholder"></div>
						<?php if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ): ?>
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid">
						<?php else: ?>
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'value', <?php echo $event['Event']['id'];?>);">
							<?php 
							endif;
								$sigDisplay = $object['value'];
								if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ) {
									$t = ($object['type'] == 0 ? 'attributes' : 'shadow_attributes');
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
									echo $this->Html->link($sigDisplay, $cveUrl . $sigDisplay, array('target' => '_blank'));
								} elseif ('link' == $object['type']) {
									echo $this->Html->link($sigDisplay, $sigDisplay);
								} else {
									$sigDisplay = str_replace("\r", '', $sigDisplay);
									echo nl2br(h($sigDisplay));
								}
							?>
						</div>
					</td>
					<td class="showspaces bitwider <?php echo $extra; ?>">
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_placeholder'; ?>" class = "inline-field-placeholder"></div>
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
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
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'to_ids', <?php echo $event['Event']['id'];?>);">
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
						<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" <?php echo $turnRed; ?> class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
							<?php if ($object['objectType'] == 0) echo h($distributionLevels[$object['distribution']]); ?>&nbsp;
						</div>
					</td>
					<td class="short action-links <?php echo $extra;?>">
						<?php
							if ($object['objectType'] == 0) {
								if ($isSiteAdmin || !$mayModify)  {
						?>
									<a href="/shadow_attributes/edit/<?php echo $object['id']; ?>" title="Propose Edit" class="icon-share useCursorPointer"></a>
						<?php 
								}
								if ($isSiteAdmin || $mayModify) {
						?>
							<a href="/attributes/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit useCursorPointer"></a>
							<span class="icon-trash useCursorPointer" onClick="deleteObject('attributes', 'delete', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
						<?php 			
								}
							} else {
								if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin) {
									echo $this->Form->create('Shadow_Attribute', array('id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'url' => '/shadow_attributes/accept/' . $object['id'], 'style' => 'display:none;'));
									echo $this->Form->end();
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
		<?php 
			endforeach;
		?>
	</table>
</div>
<?php if ($pageCount > 1): ?>
<span id = "current_page" style="visibility:hidden;"><?php echo $page;?></span>
<p>Page <?php echo $page; ?> of <?php echo $pageCount;?>, showing <?php echo count($eventArray); ?> records out of <?php echo $objectCount; ?> total, starting on <?php echo $startRecord;?>, ending on <?php echo $endRecord; ?></p>
<div class="pagination">
	<ul style="margin-right:20px;">
		<?php if ($page == 1) : ?>
			<li class="prev"><span>« previous</span></li>
		<?php else: ?>
			<li class="prev"><a href="" id = "bprev" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', <?php echo $page-1; ?>);return false;">« previous</a></li>
		<?php endif; 
		for ($i = 1; $i < (1+$pageCount); $i++): 
			if ($page != $i):
		?>
				<li><a href="" id = "bpage<?php echo $i; ?>" data-page-value="<?php echo $i; ?>" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', <?php echo $i; ?>);return false;"><?php echo $i; ?></a></li>
		<?php
			else:
		?>
				<li><span id = "bpageCurrent" class = "red bold"><?php echo $i; ?></span></li>
		<?php 
			endif;
		endfor;
		if ($page >= $pageCount): ?>
			<li class="next"><span>next »</span></li>
		<?php else: ?>
			<li class="next"><a href="" id = "bnext" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', <?php echo $page+1; ?>);return false;">next »</a></li>
		<?php endif; 
		if ($page == 'all'): ?>
			<li class="all red bold"><span>View All</span></li>
		<?php else: ?>
			<li class="all"><a href="" id = "ball" onClick="updateIndex(<?php echo $event['Event']['id']; ?>, 'event', 'all');return false;">View All</a></li>
		<?php endif; ?>
	</ul>
</div>
<?php 
	endif; 
?>
<script type="text/javascript">
	var all = 1;
	var page = "<?php echo $page; ?>";
	var count = <?php echo $pageCount; ?>;
	$(document).ready(function(){
		$('input:checkbox').removeAttr('checked');
		$('.mass-select').hide();
		$('.mass-proposal-select').hide();
		$('.select_attribute, .select_all').click(function(){
			attributeListAnyAttributeCheckBoxesChecked();
		});
		$('.select_proposal, .select_all').click(function(){
			attributeListAnyProposalCheckBoxesChecked();
		});
		if (<?php echo $pageCount; ?> > 10) restrictEventViewPagination();
	});
</script>
<?php 
	echo $this->Js->writeBuffer();
?>