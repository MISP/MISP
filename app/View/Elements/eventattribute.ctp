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
		$attributeSightingsPopover = array();
		if (isset($event['Sighting']) && !empty($event['Sighting'])) {
			foreach ($event['Sighting'] as $sighting) {
				$attributeSightings[$sighting['attribute_id']][] = $sighting;
				if (isset($sighting['org_id']) && $sighting['org_id'] == $me['org_id']) {
					if (isset($attributeOwnSightings[$sighting['attribute_id']])) $attributeOwnSightings[$sighting['attribute_id']]++;
					else $attributeOwnSightings[$sighting['attribute_id']] = 1;
				}
				if (isset($sighting['org_id'])) {
					if (isset($attributeSightingsPopover[$sighting['attribute_id']][$sighting['Organisation']['name']])) {
						$attributeSightingsPopover[$sighting['attribute_id']][$sighting['Organisation']['name']]++;
					} else {
						$attributeSightingsPopover[$sighting['attribute_id']][$sighting['Organisation']['name']] = 1;
					}
				} else {
					if (isset($attributeSightingsPopover[$sighting['attribute_id']]['Other organisations'])) {
						$attributeSightingsPopover[$sighting['attribute_id']]['Other organisations']++;
					} else {
						$attributeSightingsPopover[$sighting['attribute_id']]['Other organisations'] = 1;
					}
				}
			}
			if (!empty($attributeSightingsPopover)) {
				$attributeSightingsPopoverText = array();
				foreach ($attributeSightingsPopover as $aid =>  &$attribute) {
					$attributeSightingsPopoverText[$aid] = '';
					foreach ($attribute as $org => $count) {
						$attributeSightingsPopoverText[$aid] .= '<span class=\'bold\'>' . h($org) . '</span>: <span class=\'green\'>' . h($count) . '</span><br />';
					}
				}
			}
		}
	}
?>
	<div class="pagination">
		<ul>
		<?php
			$url = array_merge(array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']), $this->request->named);
			$this->Paginator->options(array(
				'url' => $url,
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
		if (!isset($attributeFilter)) $attributeFilter = 'all';
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
	<div class="tabMenu tabMenuToolsBlock noPrint">
		<?php if ($mayModify): ?>
			<span id="create-button" title="Populate using a template" class="icon-list-alt useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'templates', 'templateChoices');"></span>
		<?php endif; ?>
		<span id="freetext-button" title="Populate using the freetext import tool" class="icon-exclamation-sign icon-inverse useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'events', 'freeTextImport');"></span>
		<?php if ($mayModify): ?>
			<span id="attribute-replace-button" title="Replace all attributes of a category/type combination within the event" class="icon-random useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'attributes', 'attributeReplace');"></span>
		<?php endif; ?>
	</div>
	<div class="tabMenu tabMenuFiltersBlock noPrint" style="padding-right:0px !important;">
		<span id="filter_header" class="attribute_filter_header">Filters: </span>
		<div id="filter_all" title="Show all attributes" class="attribute_filter_text<?php if ($attributeFilter == 'all') echo '_active'; ?>" onClick="filterAttributes('all', '<?php echo h($event['Event']['id']); ?>');">All</div>
		<?php foreach ($typeGroups as $group): ?>
			<div id="filter_<?php echo $group; ?>" title="Only show <?php echo $group; ?> related attributes" class="attribute_filter_text<?php if ($attributeFilter == $group) echo '_active'; ?>" onClick="filterAttributes('<?php echo $group; ?>', '<?php echo h($event['Event']['id']); ?>');"><?php echo ucfirst($group); ?></div>
		<?php endforeach; ?>
		<div id="filter_proposal" title="Only show proposals" class="attribute_filter_text<?php if ($attributeFilter == 'proposal') echo '_active'; ?>" onClick="filterAttributes('proposal', '<?php echo h($event['Event']['id']); ?>');">Proposal</div>
		<div id="filter_correlation" title="Only show correlating attributes" class="attribute_filter_text<?php if ($attributeFilter == 'correlation') echo '_active'; ?>" onClick="filterAttributes('correlation', '<?php echo h($event['Event']['id']); ?>');">Correlation</div>
		<div id="filter_warning" title="Only show potentially false positive attributes" class="attribute_filter_text<?php if ($attributeFilter == 'warning') echo '_active'; ?>" onClick="filterAttributes('warning', '<?php echo h($event['Event']['id']); ?>');">Warnings</div>
		<?php if ($me['Role']['perm_sync'] || $event['Orgc']['id'] == $me['org_id']): ?>
			<div id="filter_deleted" title="Include deleted attributes" class="attribute_filter_text<?php if ($deleted) echo '_active'; ?>" onClick="toggleDeletedAttributes('<?php echo Router::url( $this->here, true );?>');">Include deleted attributes</div>
		<?php endif; ?>
	</div>

	<table class="table table-striped table-condensed">
		<tr>
			<?php if ($mayModify && !empty($event['objects'])): ?>
				<th><input class="select_all" type="checkbox" onClick="toggleAllAttributeCheckboxes();" /></th>
			<?php endif;?>
			<th><?php echo $this->Paginator->sort('date');?></th>
			<th><?php echo $this->Paginator->sort('Org.name', 'Org'); ?>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<th>Related Events</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
			<th title="<?php echo $attrDescriptions['distribution']['desc'];?>"><?php echo $this->Paginator->sort('distribution');?></th>
			<?php if (Configure::read('Plugin.Sightings_enable')): ?>
				<th>Sightings</th>
			<?php endif; ?>
			<th class="actions">Actions</th>
		</tr>
		<?php
			foreach ($event['objects'] as $k => $object):
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
				if (isset($object['deleted']) && $object['deleted']) {
					$extra .= ' background-light-red';
				}
				$extra .= (isset($object['deleted']) && $object['deleted']) ? ' background-light-red' : '';
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
							for ($i = 0; $i < 9; $i++):
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
							<td class="short <?php echo $extra; ?>">
						<?php
							if ($object['objectType'] != 0) {
								if (isset($object['Org']['name'])) {
									$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS . h($object['Org']['name']) . '.png';
									if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($object['Org']['name']) . '.png', array('alt' => h($object['Org']['name']), 'title' => h($object['Org']['name']), 'style' => 'width:24px; height:24px'));
									else echo h($object['Org']['name']);
								}
							} else { ?>
							&nbsp;
						<?php
							}
						?>
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
							<td id="<?php echo h($currentType) . '_' . h($object['id']) . '_container'; ?>" class="showspaces <?php echo $extra; ?> limitedWidth">
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class = "inline-field-placeholder"></div>
								<?php
									if ('attachment' !== $object['type'] && 'malware-sample' !== $object['type']) $editable = ' ondblclick="activateField(\'' . $currentType . '\', \'' . $object['id'] . '\', \'value\', \'' . $event['Event']['id'] . '\');"';
									else $editable = '';
								?>
								<div id = "<?php echo $currentType; ?>_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid" <?php echo $editable; ?>>
									<span <?php if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) echo 'onMouseOver="hoverModuleExpand(\'' . $currentType . '\', \'' . $object['id'] . '\');";'?>>
										<?php
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
											} else if (strpos($object['type'], '|') !== false) {
												$filenameHash = explode('|', $object['value']);
												echo h($filenameHash[0]);
												if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
											} else if ('vulnerability' == $object['type']) {
												if (! is_null(Configure::read('MISP.cveurl'))) {
													$cveUrl = Configure::read('MISP.cveurl');
												} else {
													$cveUrl = "http://www.google.com/search?q=";
												}
												echo $this->Html->link($sigDisplay, $cveUrl . $sigDisplay, array('target' => '_blank'));
											} else if ('link' == $object['type']) {
												echo $this->Html->link($sigDisplay, $sigDisplay);
											} else if ('text' == $object['type']) {
												$sigDisplay = str_replace("\r", '', h($sigDisplay));
												$sigDisplay = str_replace(" ", '&nbsp;', $sigDisplay);
												echo nl2br($sigDisplay);
											} else {
												$sigDisplay = str_replace("\r", '', $sigDisplay);
												echo nl2br(h($sigDisplay));
											}
											if (isset($object['validationIssue'])) echo ' <span class="icon-warning-sign" title="Warning, this doesn\'t seem to be a legitimage ' . strtoupper(h($object['type'])) . ' value">&nbsp;</span>';
										?>
									</span>
									<?php
										if (isset($object['warnings'])) {
											$temp = '';
											$components = array(1 => 0, 2 => 1);
											$valueParts = explode('|', $object['value']);
											foreach ($components as $component => $valuePart) {
												if (isset($object['warnings'][$component]) && isset($valueParts[$valuePart])) {
													foreach ($object['warnings'][$component] as $warning) $temp .= '<span class=\'bold\'>' . h($valueParts[$valuePart]) . '</span>: <span class=\'red\'>' . h($warning) . '</span><br />';
												}
											}
											echo ' <span class="icon-warning-sign" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover">&nbsp;</span>';
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
										if ($object['objectType'] == 0) {
											$relatedObject = 'Attribute';
											$otherColour = $object['hasChildren'] == 0 ? 'blue' : 'white';
										} else {
											$relatedObject = 'ShadowAttribute';
											$otherColour = 'white';
										}
										$relatedObject = $object['objectType'] == 0 ? 'Attribute' : 'ShadowAttribute';

										if (isset($event['Related' . $relatedObject][$object['id']]) && (null != $event['Related' . $relatedObject][$object['id']])) {
											foreach ($event['Related' . $relatedObject][$object['id']] as $relatedAttribute) {
												$relatedData = array('Event info' => $relatedAttribute['info'], 'Correlating Value' => $relatedAttribute['value'], 'date' => $relatedAttribute['date']);
												$popover = '';
												foreach ($relatedData as $k => $v) {
													$popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
												}
												echo '<li style="padding-right: 0px; padding-left:0px;"  data-toggle="popover" data-content="' . h($popover) . '" data-trigger="hover"><span>';
												if ($relatedAttribute['org_id'] == $me['org_id']) {
													echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']), array ('class' => 'red'));
												} else {
													echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']), array ('class' => $otherColour));
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
							if ($object['objectType'] == 0):
								echo $this->Form->create('Sighting', array('id' => 'Sighting_' . $object['id'], 'url' => '/sightings/add/' . $object['id'], 'style' => 'display:none;'));
								echo $this->Form->end();
						?>
						</span>
						<span class="icon-thumbs-up useCursorPointer" onClick="addSighting('<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']);?>', '<?php echo h($page); ?>');">&nbsp;</span>
						<span id="sightingCount_<?php echo h($object['id']); ?>" class="bold sightingsCounter_<?php echo h($object['id']); ?>"  data-toggle="popover" data-trigger="hover" data-content="<?php echo isset($attributeSightingsPopoverText[$object['id']]) ? $attributeSightingsPopoverText[$object['id']] : ''; ?>">
							<?php echo (!empty($attributeSightings[$object['id']]) ? count($attributeSightings[$object['id']]) : 0); ?>
						</span>
						<span id="ownSightingCount_<?php echo h($object['id']); ?>" class="bold green sightingsCounter_<?php echo h($object['id']); ?>" data-toggle="popover" data-trigger="hover" data-content="<?php echo isset($attributeSightingsPopoverText[$object['id']]) ? $attributeSightingsPopoverText[$object['id']] : ''; ?>">
							<?php echo '(' . (isset($attributeOwnSightings[$object['id']]) ? $attributeOwnSightings[$object['id']] : 0) . ')'; ?>
						</span>
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
								if ($object['deleted']):
									if ($isSiteAdmin || $mayModify):
							?>
									<span class="icon-repeat useCursorPointer" onClick="deleteObject('attributes', 'restore', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
									<span class="icon-trash useCursorPointer" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
							<?php
									endif;
								else:
									if ($isSiteAdmin || !$mayModify):
										if (isset($modules) && isset($modules['types'][$object['type']])):
							?>
								<span class="icon-asterisk useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/ShadowAttribute');" title="Propose enrichment">&nbsp;</span>
							<?php
										endif;
							?>
										<a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?php echo $object['id']; ?>" title="Propose Edit" class="icon-share useCursorPointer"></a>
										<span class="icon-trash useCursorPointer" title="Propose Deletion" onClick="deleteObject('shadow_attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
							<?php
										if ($isSiteAdmin):
							?>
											<span class="verticalSeparator">&nbsp;</span>
							<?php		endif;
									endif;
									if ($isSiteAdmin || $mayModify) {
										if (isset($modules) && isset($modules['types'][$object['type']])):
							?>
								<span class="icon-asterisk useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/Attribute');" title="Add enrichment">&nbsp;</span>
							<?php
										endif;
							?>
								<a href="<?php echo $baseurl;?>/attributes/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit useCursorPointer"></a>
								<span class="icon-trash useCursorPointer" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
							<?php
									}
								endif;
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
	<?php if (!isset($event['objects']) || empty($event['objects'])): ?>
		<div class="background-red bold">
			<span>
			<?php
				if ($me['org_id'] != $event['Event']['orgc_id']) {
					echo 'Attribute warning: This event doesn\'t have any attributes visible to you. Either the owner of the event decided to have
a specific distribution scheme per attribute and wanted to still distribute the event alone either for notification or potential contribution with attributes without such restriction. Or the owner forgot to add the
attributes or the appropriate distribution level. If you think there is a mistake or you can contribute attributes based on the event meta-information, feel free to make a proposal';
				} else {
					echo 'Attribute warning: This event doesn\'t contain any attribute. It\'s strongly advised to populate the event with attributes (indicators, observables or information) to provide a meaningful event';
				}
			?>
			</span>
		</div>
	<?php endif;?>
	<div class="pagination">
  	  <ul>
		<?php
			$url = array_merge(array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']), $this->request->named);
			$this->Paginator->options(array(
				'url' => $url,
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
	var currentUri = "<?php echo isset($currentUri) ? h($currentUri) : '/events/viewEventAttributes/' . h($event['Event']['id']); ?>";
	var ajaxResults = [];
	var deleted = <?php echo (isset($deleted) && $deleted) ? 'true' : 'false';?>;
	$(document).ready(function(){
		popoverStartup();
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
