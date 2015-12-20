<?php
	$mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
	$possibleAction = 'Proposal';
	if ($mayModify) $possibleAction = 'Attribute';
	$all = false;
	if (isset($this->params->params['paging']['Event']['page'])) {
		if ($this->params->params['paging']['Event']['page'] == 0) $all = true;
		$page = $this->params->params['paging']['Event']['page'];
	} else {
		$page = 0;
	}
	if (Configure::read('Plugin.Sightings_enable')) {
		$attributeSightings = array();
		$attributeOwnSightings = array();
		if (isset($event['Sighting']) && !empty($event['Sighting'])) {
			foreach ($event['Sighting'] as $sighting) {
				$attributeSightings[$sighting['attribute_id']][] = $sighting;
				if (isset($sighting['org_id']) && $sighting['org_id'] == $me['org_id']) {
					if (isset($attributeOwnSightings[$sighting['attribute_id']])) $attributeOwnSightings[$sighting['attribute_id']]++;
					else $attributeOwnSightings[$sighting['attribute_id']] = 1;
				}
			}	
		}
	}
?>
	<div class="pagination">
        <ul>
        <?php
	        $this->Paginator->options(array(
	        	'url' => array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']),
	            'update' => '#attributes_div',
	            'evalScripts' => true,
	            'before' => '$(".progress").show()',
	            'complete' => '$(".progress").hide()',
	        ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
		<li class="all <?php if ($all) echo 'disabled'; ?>">
			<?php
				if ($all):
			?>
				<span class="red">view all</span>
			<?php 
				else:
					echo $this->Paginator->link(__('view all'), 'all'); 
				endif;
			?>
		</li>
        </ul>
    </div>
<br />
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
			<?php if ($mayModify && !empty($event['objects'])): ?>
				<th><input class="select_all" type="checkbox" onClick="toggleAllAttributeCheckboxes();" /></th>
			<?php endif;?>
			<th><?php echo $this->Paginator->sort('date');?></th>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<th>Related Events</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
			<th title="<?php echo $attrDescriptions['distribution']['desc'];?>"><?php echo $this->Paginator->sort('distribution');?></th>
			<?php if (Configure::read('Plugin.Sightings_enable'))?><th>Sightings</th>
			<th class="actions">Actions</th>
		</tr>
		<?php 
			foreach($event['objects'] as $k => $object):
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
				} else {
					if (isset($object['proposal_to_delete']) && $object['proposal_to_delete']) {
						$extra = 'highlight3';
						unset($object['type']);
					} else $extra = 'highlight2';
					
				}
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
					<?php endif; 
						if (isset($object['proposal_to_delete']) && $object['proposal_to_delete']): 
							for ($i = 0; $i < 8; $i++): 	
					?>
								<td class="<?php echo $extra; ?>" style="font-weight:bold;"><?php echo ($i == 0 ? 'DELETE' : '&nbsp;'); ?></td>
					<?php 
							endfor;
						else:
					?>
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
								<?php if ('attachment' === $object['type'] || 'malware-sample' === $object['type'] ): ?>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid">
								<?php else: ?>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'value', <?php echo $event['Event']['id'];?>);">
									<?php 
									endif;
										$sigDisplay = $object['value'];
										if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ) {
											$t = ($object['objectType'] == 0 ? 'attributes' : 'shadow_attributes');
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
										if (isset($object['validationIssue'])) echo ' <span class="icon-warning-sign" title="Warning, this doesn\'t seem to be a legitimage ' . strtoupper(h($object['type'])) . ' value">&nbsp;</span>';
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
										if ($object['objectType'] == 0 && isset($event['RelatedAttribute'][$object['id']]) && (null != $event['RelatedAttribute'][$object['id']])) {
											foreach ($event['RelatedAttribute'][$object['id']] as $relatedAttribute) {
												echo '<li style="padding-right: 0px; padding-left:0px;" title ="' . h($relatedAttribute['info']) . '"><span>';
												if ($relatedAttribute['org_id'] == $me['org_id']) {
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
							<td class="shortish <?php echo $extra; ?>">
								<?php 
									$turnRed = '';
									if ($object['objectType'] == 0 && $object['distribution'] == 0) $turnRed = 'style="color:red"';
								?>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_placeholder'; ?>" class = "inline-field-placeholder"></div>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" <?php echo $turnRed; ?> class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
									<?php 
										if ($object['objectType'] == 0) {
											if ($object['distribution'] == 4):
									?>
											<a href="/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
									<?php 
											else: 
												echo h($shortDist[$object['distribution']]); 
											endif;
										}
									?>&nbsp;
								</div>
							</td>
					<?php 
						endif;
						if (Configure::read('Plugin.Sightings_enable')):
					?>
					<td class="short <?php echo $extra;?>">
						<span id="sightingForm_<?php echo h($object['id']);?>">
						<?php 
							if($object['objectType'] == 0):
								echo $this->Form->create('Sighting', array('id' => 'Sighting_' . $object['id'], 'url' => '/sightings/add/' . $object['id'], 'style' => 'display:none;'));
								echo $this->Form->end();
						?>
						</span>
						<span class="icon-thumbs-up useCursorPointer" onClick="addSighting('<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']);?>', '<?php echo h($page); ?>');">&nbsp;</span>
						<span id="sightingCount_<?php echo h($object['id']); ?>" class="bold sightingsCounter_<?php echo h($object['id']); ?>"><?php echo (!empty($attributeSightings[$object['id']]) ? count($attributeSightings[$object['id']]) : 0); ?></span>
						(<span id="ownSightingCount_<?php echo h($object['id']); ?>" class="bold green sightingsCounter_<?php echo h($object['id']); ?>"><?php echo (isset($attributeOwnSightings[$object['id']]) ? $attributeOwnSightings[$object['id']] : 0); ?></span>)
						<?php 
							endif;
						?>
					</td>
					<?php 
						endif;
					?>
					<td class="short action-links <?php echo $extra;?>">
						<?php
							if ($object['objectType'] == 0) {
								if ($isSiteAdmin || !$mayModify):
						?>
									<a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?php echo $object['id']; ?>" title="Propose Edit" class="icon-share useCursorPointer"></a>
									<span class="icon-trash useCursorPointer" title="Propose Deletion" onClick="deleteObject('shadow_attributes', 'delete', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
						<?php 
									if ($isSiteAdmin): 
						?>
										<span class="verticalSeparator">&nbsp;</span>
						<?php 		endif;
								endif;
								if ($isSiteAdmin || $mayModify) {
						?>
							<a href="<?php echo $baseurl;?>/attributes/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit useCursorPointer"></a>
							<span class="icon-trash useCursorPointer" onClick="deleteObject('attributes', 'delete', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
						<?php 			
								}
							} else {
								if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin) {
									echo $this->Form->create('Shadow_Attribute', array('id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'url' => '/shadow_attributes/accept/' . $object['id'], 'style' => 'display:none;'));
									echo $this->Form->end();
								?>
									<span class="icon-ok useCursorPointer" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
								<?php 
								}
								if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin || ($object['org_id'] == $me['org_id'])) {
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
	<div class="pagination">
        <ul>
        <?php
	        $this->Paginator->options(array(
				'url' => array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']),
	            'update' => '#attributes_div',
	            'evalScripts' => true,
	            'before' => '$(".progress").show()',
	            'complete' => '$(".progress").hide()',
	        ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
		<li class="all <?php if ($all) echo 'disabled'; ?>">
			<?php
				if ($all):
			?>
				<span class="red">view all</span>
			<?php 
				else:
					echo $this->Paginator->link(__('view all'), 'all'); 
				endif;
			?>
		</li>
        </ul>
    </div>
<script type="text/javascript">
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
	});
</script>
<?php 
	echo $this->Js->writeBuffer();
?>