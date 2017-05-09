<?php
	$mayModify = ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
	$mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
	$possibleAction = 'Proposal';
	if ($mayModify) $possibleAction = 'Attribute';
	$all = false;
	if (isset($this->params->params['paging']['Event']['page'])) {
		if ($this->params->params['paging']['Event']['page'] == 0) $all = true;
		$page = $this->params->params['paging']['Event']['page'];
	} else {
		$page = 0;
	}
	if (Configure::read('Plugin.Sightings_enable') !== false) {
		if (!empty($event['Sighting'])) {
			foreach ($sightingsData['data'] as $aid => $data) {
				$sightingsData['data'][$aid]['html'] = '';
				foreach ($data as $type => $typeData) {
					$name = (($type != 'expiration') ? Inflector::pluralize($type) : $type);
					$sightingsData['data'][$aid]['html'] .= '<span class=\'blue bold\'>' . ucfirst(h($name)) . '</span><br />';
					foreach ($typeData['orgs'] as $org => $orgData) {
						$extra = (($org == $me['Organisation']['name']) ? " class=	'bold'" : "");
						if ($type == 'expiration') {
							$sightingsData['data'][$aid]['html'] .= '<span ' . $extra . '>' . h($org) . '</span>: <span class=\'orange bold\'>' . date('Y-m-d H:i:s', $orgData['date']) . '</span><br />';
						} else {
							$sightingsData['data'][$aid]['html'] .= '<span ' . $extra . '>' . h($org) . '</span>: <span class=\'' . (($type == 'sighting') ? 'green' : 'red') . ' bold\'>' . h($orgData['count']) . ' (' . date('Y-m-d H:i:s', $orgData['date']) . ')</span><br />';
						}
					}
					$sightingsData['data'][$aid]['html'] .= '<br />';
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
		<span id="create-button" title="Add attribute" role="button" tabindex="0" aria-label="Add attribute" class="icon-plus useCursorPointer" onClick="clickCreateButton(<?php echo $event['Event']['id']; ?>, '<?php echo $possibleAction; ?>');"></span>
		<span id="multi-edit-button" title="Edit selected Attributes" role="button" tabindex="0" aria-label="Edit selected Attributes" class="hidden icon-edit mass-select useCursorPointer" onClick="editSelectedAttributes(<?php echo $event['Event']['id']; ?>);"></span>
		<span id="multi-tag-button" title="Tag selected Attributes" role="button" tabindex="0" aria-label="Tag selected Attributes" class="hidden icon-tag mass-select useCursorPointer" onClick="getPopup('selected/true', 'tags', 'selectTaxonomy');"></span>
		<span id="multi-delete-button" title="Delete selected Attributes" role="button" tabindex="0" aria-label="Delete selected Attributes" class="hidden icon-trash mass-select useCursorPointer" onClick="multiSelectAction(<?php echo $event['Event']['id']; ?>, 'deleteAttributes');"></span>
		<span id="multi-accept-button" title="Accept selected Proposals" role="button" tabindex="0" aria-label="Accept selected Proposals" class="hidden icon-ok mass-proposal-select useCursorPointer" onClick="multiSelectAction(<?php echo $event['Event']['id']; ?>, 'acceptProposals');"></span>
		<span id="multi-discard-button" title="Discard selected Proposals" role="button" tabindex="0" aria-label="Discard selected Proposals" class="hidden icon-remove mass-proposal-select useCursorPointer" onClick="multiSelectAction(<?php echo $event['Event']['id']; ?>, 'discardProposals');"></span>
		<?php if (Configure::read('Plugin.Sightings_enable')): ?>
			<span id="multi-sighting-button" title="Sightings display for selected attributes" role="button" tabindex="0" aria-label="Sightings display for selected attributes" class="hidden icon-wrench mass-select useCursorPointer sightings_advanced_add" data-object-id="selected" data-object-context="attribute"></span>
		<?php endif; ?>
	</div>
	<div class="tabMenu tabMenuToolsBlock noPrint">
		<?php if ($mayModify): ?>
			<span id="create-button" title="Populate using a template" role="button" tabindex="0" aria-label="Populate using a template" class="icon-list-alt useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'templates', 'templateChoices');"></span>
		<?php endif; ?>
		<span id="freetext-button" title="Populate using the freetext import tool" role="button" tabindex="0" aria-label="Populate using the freetext import tool" class="icon-exclamation-sign icon-inverse useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'events', 'freeTextImport');"></span>
		<?php if ($mayModify): ?>
			<span id="attribute-replace-button" title="Replace all attributes of a category/type combination within the event" role="button" tabindex="0" aria-label="Replace all attributes of a category/type combination within the event" class="icon-random useCursorPointer" onClick="getPopup(<?php echo $event['Event']['id']; ?>, 'attributes', 'attributeReplace');"></span>
		<?php endif; ?>
	</div>
	<div class="tabMenu tabMenuFiltersBlock noPrint" style="padding-right:0px !important;">
		<span id="filter_header" class="attribute_filter_header">Filters: </span>
		<div id="filter_all" title="Show all attributes" role="button" tabindex="0" aria-label="Show all attributes" class="attribute_filter_text<?php if ($attributeFilter == 'all') echo '_active'; ?>" onClick="filterAttributes('all', '<?php echo h($event['Event']['id']); ?>');">All (<?php echo h($this->Paginator->params()['total_elements']); ?>)</div>
		<?php foreach ($typeGroups as $group): ?>
			<div id="filter_<?php echo h($group); ?>" title="Only show <?php echo $group; ?> related attributes" role="button" tabindex="0" aria-label="Only show <?php echo h($group); ?> related attributes" class="attribute_filter_text<?php if ($attributeFilter == $group) echo '_active'; ?>" onClick="filterAttributes('<?php echo $group; ?>', '<?php echo h($event['Event']['id']); ?>');"><?php echo ucfirst($group); ?></div>
		<?php endforeach; ?>
		<div id="filter_proposal" title="Only show proposals" role="button" tabindex="0" aria-label="Only show proposals" class="attribute_filter_text<?php if ($attributeFilter == 'proposal') echo '_active'; ?>" onClick="filterAttributes('proposal', '<?php echo h($event['Event']['id']); ?>');">Proposal</div>
		<div id="filter_correlation" title="Only show correlating attributes" role="button" tabindex="0" aria-label="Only show correlating attributes" class="attribute_filter_text<?php if ($attributeFilter == 'correlation') echo '_active'; ?>" onClick="filterAttributes('correlation', '<?php echo h($event['Event']['id']); ?>');">Correlation</div>
		<div id="filter_warning" title="Only show potentially false positive attributes" role="button" tabindex="0" aria-label="Only show potentially false positive attributes" class="attribute_filter_text<?php if ($attributeFilter == 'warning') echo '_active'; ?>" onClick="filterAttributes('warning', '<?php echo h($event['Event']['id']); ?>');">Warnings</div>
		<?php if ($me['Role']['perm_sync'] || $event['Orgc']['id'] == $me['org_id']): ?>
			<div id="filter_deleted" title="Include deleted attributes" role="button" tabindex="0" aria-label="Include deleted attributes" class="attribute_filter_text<?php if ($deleted) echo '_active'; ?>" onClick="toggleDeletedAttributes('<?php echo Router::url( $this->here, true );?>');">Include deleted attributes</div>
		<?php endif; ?>
		<div id="show_context" title="Show attribute context fields" role="button" tabindex="0" aria-label="Show attribute context fields" class="attribute_filter_text" onClick="toggleContextFields();">Show context fields</div>
	</div>

	<table class="table table-striped table-condensed">
		<tr>
			<?php if ($mayModify && !empty($event['objects'])): ?>
				<th><input class="select_all" type="checkbox" title="Select all" role="button" tabindex="0" aria-label="Select all attributes/proposals on current page" onClick="toggleAllAttributeCheckboxes();" /></th>
			<?php endif;?>
			<th class="context hidden"><?php echo $this->Paginator->sort('id');?></th>
			<th class="context hidden">UUID</th>
			<th><?php echo $this->Paginator->sort('timestamp', 'Date');?></th>
			<th><?php echo $this->Paginator->sort('Org.name', 'Org'); ?>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th>Tags</th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<?php
				if ($mayChangeCorrelation && !$event['Event']['disable_correlation']):
			?>
					<th>Correlate</th>
			<?php
				endif;
			?>
			<th>Related Events</th>
			<th>Feed hits</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
			<th title="<?php echo $attrDescriptions['distribution']['desc'];?>"><?php echo $this->Paginator->sort('distribution');?></th>
			<?php if (Configure::read('Plugin.Sightings_enable') !== false): ?>
				<th>Sightings</th>
				<th>Activity</th>
			<?php endif; ?>
			<th class="actions">Actions</th>
		</tr>
		<?php
			foreach ($event['objects'] as $k => $object):
				$extra = '';
				$extra2 = '';
				$extra3 = '';
				$linkClass = 'white';
				$currentType = 'denyForm';
				if ($object['objectType'] == 0 ) {
					$currentType = 'Attribute';
					if ($object['hasChildren'] == 1) {
						$extra = 'highlight1';
						$extra3 = 'highlightBlueSides highlightBlueTop';
					} else {
						$linkClass = '';
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
						<td class="<?php echo $extra; ?>" style="width:10px;" data-position="<?php echo h($k); ?>">
							<?php if ($object['objectType'] == 0): ?>
								<input id = "select_<?php echo $object['id']; ?>" class="select_attribute row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" />
							<?php else: ?>
								<input id = "select_proposal_<?php echo $object['id']; ?>" class="select_proposal row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" />
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
							<td class="short context hidden <?php echo $extra; ?>"><?php echo $object['objectType'] == 0 ? h($object['id']) : '&nbsp;'; ?></td>
							<td class="short context hidden <?php echo $extra; ?>"><?php echo $object['objectType'] == 0 ? h($object['uuid']) : '&nbsp;'; ?></td>
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
							<td class="short <?php echo $extra; ?>">
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_category_placeholder'; ?>" class = "inline-field-placeholder"></div>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
									<?php echo h($object['category']); ?>
								</div>
							</td>
							<td class="short <?php echo $extra; ?>">
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_placeholder'; ?>" class = "inline-field-placeholder"></div>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
									<?php echo h($object['type']); ?>
								</div>
							</td>
							<td id="<?php echo h($currentType) . '_' . h($object['id']) . '_container'; ?>" class="showspaces <?php echo $extra; ?> limitedWidth shortish">
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class = "inline-field-placeholder"></div>
								<?php
									if ('attachment' !== $object['type'] && 'malware-sample' !== $object['type']) $editable = ' ondblclick="activateField(\'' . $currentType . '\', \'' . $object['id'] . '\', \'value\', \'' . $event['Event']['id'] . '\');"';
									else $editable = '';
								?>
								<div id = "<?php echo $currentType; ?>_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid" <?php echo $editable; ?>>
									<span <?php if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) echo 'class="eventViewAttributeHover" data-object-type="' . h($currentType) . '" data-object-id="' . h($object['id']) . '"'?>>
										<?php
											$sigDisplay = $object['value'];
											if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ) {
												if ($object['type'] == 'attachment' && isset($object['image'])) {
													$extension = explode('.', $object['value']);
													$extension = end($extension);
													$uri = 'data:image/' . strtolower(h($extension)) . ';base64,' . h($object['image']);
													echo '<img class="screenshot screenshot-collapsed useCursorPointer" src="' . $uri . '" title="' . h($object['value']) . '" />';
												} else {
													$t = ($object['objectType'] == 0 ? 'attributes' : 'shadow_attributes');
													$filenameHash = explode('|', nl2br(h($object['value'])));
													if (strrpos($filenameHash[0], '\\')) {
														$filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
														$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
														echo h($filepath);
														echo '<a href="' . $baseurl . '/' . h($t) . '/download/' . h($object['id']) . '" class="' . $linkClass . '">' . h($filename) . '</a>';
													} else {
														echo '<a href="' . $baseurl . '/' . h($t) . '/download/' . h($object['id']) . '" class="' . $linkClass . '">' . h($filenameHash[0]) . '</a>';
													}
													if (isset($filenameHash[1])) echo '<br />' . $filenameHash[1];
												}
											} else if (strpos($object['type'], '|') !== false) {
												$filenameHash = explode('|', $object['value']);
												echo h($filenameHash[0]);
												if (isset($filenameHash[1])) {
													$separator = '<br />';
													if (in_array($object['type'], array('ip-dst|port', 'ip-src|port'))) {
														$separator = ':';
													}
													echo $separator . h($filenameHash[1]);
												}
											} else if ('vulnerability' == $object['type']) {
												if (! is_null(Configure::read('MISP.cveurl'))) {
													$cveUrl = Configure::read('MISP.cveurl');
												} else {
													$cveUrl = "http://www.google.com/search?q=";
												}
												echo $this->Html->link($sigDisplay, $cveUrl . $sigDisplay, array('target' => '_blank', 'class' => $linkClass));
											} else if ('link' == $object['type']) {
												echo $this->Html->link($sigDisplay, $sigDisplay, array('class' => $linkClass));
											} else if ('cortex' == $object['type']) {
												echo '<div class="cortex-json" data-cortex-json="' . h($object['value']) . '">Cortex object</div>';
											} else if ('text' == $object['type']) {
												if ($object['category'] == 'External analysis' && preg_match('/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i', $object['value'])) {
													echo '<a href="' . $baseurl . '/events/view/' . h($object['value']) . '" class="' . $linkClass . '">' . h($object['value']) . '</a>';
												} else {
													$sigDisplay = str_replace("\r", '', h($sigDisplay));
													$sigDisplay = str_replace(" ", '&nbsp;', $sigDisplay);
													echo nl2br($sigDisplay);
												}
											} else if ('hex' == $object['type']) {
												$sigDisplay = str_replace("\r", '', $sigDisplay);
												echo '<span class="hex-value" title="Hexadecimal representation">' . nl2br(h($sigDisplay)) . '</span>&nbsp;<span role="button" tabindex="0" aria-label="Switch to binary representation" class="icon-repeat hex-value-convert useCursorPointer" title="Switch to binary representation"></span>';
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
							<td class="shortish <?php echo $extra; ?>">
								<?php
									if ($object['objectType'] == 0):
								?>
									<div class="attributeTagContainer">
										<?php echo $this->element('ajaxAttributeTags', array('attributeId' => $object['id'], 'attributeTags' => $object['AttributeTag'], 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id']) )); ?>
									</div>
								<?php
									else:
								?>
									&nbsp;
								<?php
									endif;
								?>
							</td>
							<td class="showspaces bitwider <?php echo $extra; ?>">
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_placeholder'; ?>" class = "inline-field-placeholder"></div>
								<div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
									<?php echo nl2br(h($object['comment'])); ?>&nbsp;
								</div>
							</td>
							<?php
								if ($mayChangeCorrelation && !$event['Event']['disable_correlation']):
									if ($object['objectType'] == 0):
							?>
										<td class="short <?php echo $extra; ?>" style="padding-top:3px;">
											<input id="correlation_toggle_<?php echo h($object['id']); ?>" class="correlation-toggle" type="checkbox" data-attribute-id="<?php echo h($object['id']); ?>" <?php echo $object['disable_correlation'] ? '' : 'checked'; ?>>
										</td>
							<?php
									else:
							?>
										<td class="short <?php echo $extra; ?>" style="padding-top:3px;">&nbsp;</td>
							<?php
									endif;
								endif;
							?>
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
												$relatedData = array('Event info' => $relatedAttribute['info'], 'Correlating Value' => $relatedAttribute['value'], 'date' => isset($relatedAttribute['date']) ? $relatedAttribute['date'] : 'N/A');
												$popover = '';
												foreach ($relatedData as $k => $v) {
													$popover .= '<span class=\'bold black\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
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
							<td class="shortish <?php echo $extra; ?>">
								<ul class="inline" style="margin:0px;">
									<?php
										if (!empty($object['Feed'])):
											foreach ($object['Feed'] as $feed):
												$popover = '';
												foreach ($feed as $k => $v):
													if ($k == 'id') continue;
													$popover .= '<span class=\'bold black\'>' . Inflector::humanize(h($k)) . '</span>: <span class="blue">' . h($v) . '</span><br />';
												endforeach;
											?>
												<li style="padding-right: 0px; padding-left:0px;"  data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover"><span>
													<?php
														if ($isSiteAdmin):
															echo $this->Html->link($feed['id'], array('controller' => 'feeds', 'action' => 'previewIndex', $feed['id']), array('style' => 'margin-right:3px;'));
														else:
													?>
														<span style="margin-right:3px;"><?php echo h($feed['id']);?></span>
													<?php
														endif;
													endforeach;
													?>
												</li>
									<?php
										endif;
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
						if (Configure::read('Plugin.Sightings_enable') !== false):
					?>
					<td class="shortish <?php echo $extra;?>">
						<span id="sightingForm_<?php echo h($object['id']);?>">
						<?php
							if ($object['objectType'] == 0):
								echo $this->Form->create('Sighting', array('id' => 'Sighting_' . $object['id'], 'url' => '/sightings/add/' . $object['id'], 'style' => 'display:none;'));
								echo $this->Form->input('type', array('label' => false, 'id' => 'Sighting_' . $object['id'] . '_type'));
								echo $this->Form->end();
						?>
						</span>
						<?php
							$temp = array();
							if (isset($sightingsData['csv'][$object['id']])) {
								$temp = $sightingsData['csv'][$object['id']];
							}
						?>
						<span class="icon-thumbs-up useCursorPointer" title="Add sighting" role="button" tabindex="0" aria-label="Add sighting" onClick="addSighting('0', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']);?>', '<?php echo h($page); ?>');">&nbsp;</span>
						<span class="icon-thumbs-down useCursorPointer" title="Mark as false-positive" role="button" tabindex="0" aria-label="Mark as false-positive" onClick="addSighting('1', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']);?>', '<?php echo h($page); ?>');">&nbsp;</span>
						<span class="icon-wrench useCursorPointer sightings_advanced_add" title="Advanced sightings"  role="button" tabindex="0" aria-label="Advanced sightings" data-object-id="<?php echo h($object['id']); ?>" data-object-context="attribute">&nbsp;</span>
						<span id="sightingCount_<?php echo h($object['id']); ?>" class="bold sightingsCounter_<?php echo h($object['id']); ?>" data-placement="top" data-toggle="popover" data-trigger="hover" data-content="<?php echo isset($sightingsData['data'][$object['id']]['html']) ? $sightingsData['data'][$object['id']]['html'] : ''; ?>">
							<?php
								$s = (!empty($sightingsData['data'][$object['id']]['sighting']['count']) ? $sightingsData['data'][$object['id']]['sighting']['count'] : 0);
								$f = (!empty($sightingsData['data'][$object['id']]['false-positive']['count']) ? $sightingsData['data'][$object['id']]['false-positive']['count'] : 0);
								$e = (!empty($sightingsData['data'][$object['id']]['expiration']['count']) ? $sightingsData['data'][$object['id']]['expiration']['count'] : 0);
							?>
						</span>
						<span id="ownSightingCount_<?php echo h($object['id']); ?>" class="bold sightingsCounter_<?php echo h($object['id']); ?>" data-placement="top" data-toggle="popover" data-trigger="hover" data-content="<?php echo isset($sightingsData['data'][$object['id']]['html']) ? $sightingsData['data'][$object['id']]['html'] : ''; ?>">
							<?php echo '(<span class="green">' . h($s) . '</span>/<span class="red">' . h($f) . '</span>/<span class="orange">' . h($e) . '</span>)'; ?>
						</span>
						<?php
							endif;
						?>
					</td>
					<td class="short <?php echo $extra; ?>">
						<?php
							if ($object['objectType'] == 0 && !empty($temp)) {
								echo $this->element('sparkline', array('id' => $object['id'], 'csv' => $temp));
							}
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
									<span class="icon-repeat useCursorPointer" title="Restore attribute" role="button" tabindex="0" aria-label="Restore attribute" onClick="deleteObject('attributes', 'restore', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
									<span class="icon-trash useCursorPointer" title="Delete attribute" role="button" tabindex="0" aria-label="Permanently delete attribute" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
							<?php
									endif;
								else:
									if ($isSiteAdmin || !$mayModify):
										if (isset($modules) && isset($modules['types'][$object['type']])):
							?>
								<span class="icon-asterisk useCursorPointer" title="Query enrichment" role="button" tabindex="0" aria-label="Query enrichment" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/ShadowAttribute');" title="Propose enrichment">&nbsp;</span>
							<?php
										endif;
										if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
							?>
								<span class="icon-eye-open useCursorPointer" title="Query Cortex" role="button" tabindex="0" aria-label="Query Cortex" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/ShadowAttribute/Cortex');" title="Propose enrichment through Cortex"></span>
							<?php
										endif;
							?>
										<a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?php echo $object['id']; ?>" title="Propose Edit" class="icon-share useCursorPointer"></a>
										<span class="icon-trash useCursorPointer" title="Propose Deletion" role="button" tabindex="0" aria-label="Propose deletion" onClick="deleteObject('shadow_attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
							<?php
										if ($isSiteAdmin):
							?>
											<span class="verticalSeparator">&nbsp;</span>
							<?php		endif;
									endif;
									if ($isSiteAdmin || $mayModify) {
										if (isset($modules) && isset($modules['types'][$object['type']])):
							?>
								<span class="icon-asterisk useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/Attribute');" title="Add enrichment" role="button" tabindex="0" aria-label="Add enrichment">&nbsp;</span>
							<?php
										endif;
										if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
							?>
								<span class="icon-eye-open useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/Attribute/Cortex');" title="Add enrichment" role="button" tabindex="0" aria-label="Add enrichment via Cortex">C</span>
							<?php
										endif;

							?>
								<a href="<?php echo $baseurl;?>/attributes/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit useCursorPointer"></a>
								<span class="icon-trash useCursorPointer" title="Delete attribute" role="button" tabindex="0" aria-label="Delete attribute" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
							<?php
									}
								endif;
							} else {
								if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin) {
									echo $this->Form->create('Shadow_Attribute', array('id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'url' => '/shadow_attributes/accept/' . $object['id'], 'style' => 'display:none;'));
									echo $this->Form->end();
								?>
									<span class="icon-ok useCursorPointer" title="Accept Proposal" role="button" tabindex="0" aria-label="Accept proposal" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
								<?php
								}
								if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin || ($object['org_id'] == $me['org_id'])) {
								?>
									<span class="icon-trash useCursorPointer" title="Discard proposal" role="button" tabindex="0" aria-label="Discard proposal" onClick="deleteObject('shadow_attributes', 'discard' ,'<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
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
	<?php if ($emptyEvent): ?>
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
	var timer;
	var lastSelected = false;
	var deleted = <?php echo (isset($deleted) && $deleted) ? 'true' : 'false';?>;
	$(document).ready(function() {
		setContextFields();
		popoverStartup();
		$('.select_attribute').removeAttr('checked');
		$('.select_proposal').removeAttr('checked');
		$('.select_attribute').click(function(e) {
			if ($(this).is(':checked')) {
				if (e.shiftKey) {
					selectAllInbetween(lastSelected, $(this).parent().data('position'));
				}
				lastSelected = $(this).parent().data('position');
			}
			attributeListAnyAttributeCheckBoxesChecked();
		});
		$('.select_proposal').click(function(e){
			if ($(this).is(':checked')) {
				if (e.shiftKey) {
					selectAllInbetween(lastSelected, $(this).parent().data('position'));
				}
				lastSelected = $(this).parent().data('position');
			}
			attributeListAnyProposalCheckBoxesChecked();
		});
		$('.select_all').click(function() {
			attributeListAnyAttributeCheckBoxesChecked();
			attributeListAnyProposalCheckBoxesChecked();
		});
		$('.correlation-toggle').click(function() {
			var attribute_id = $(this).data('attribute-id');
			getPopup(attribute_id, 'attributes', 'toggleCorrelation', '', '#confirmation_box');
			return false;
		});
		$('.screenshot').click(function() {
			screenshotPopup($(this).attr('src'), $(this).attr('title'));
		});
		$('.sightings_advanced_add').click(function() {
			var selected = [];
			var object_context = $(this).data('object-context');
			var object_id = $(this).data('object-id');
			if (object_id == 'selected') {
				$(".select_attribute").each(function() {
					if ($(this).is(":checked")) {
						selected.push($(this).data("id"));
					}
				});
				object_id = selected.join('|');
			}
			url = "<?php echo $baseurl; ?>" + "/sightings/advanced/" + object_id + "/" + object_context;
			genericPopup(url, '#screenshot_box');
		});
	});
	$('.hex-value-convert').click(function() {
		var val = $(this).parent().children(':first-child').text();
		if ($(this).parent().children(':first-child').attr('data-original-title') == 'Hexadecimal representation') {
			var bin = [];
			var temp;
			val.split('').forEach(function(entry) {
				temp = parseInt(entry, 16).toString(2);
				bin.push(Array(5 - (temp.length)).join('0') + temp);
			});
			bin = bin.join(' ');
			$(this).parent().children(':first-child').text(bin);
			$(this).parent().children(':first-child').attr('data-original-title', 'Binary representation');
			$(this).parent().children(':nth-child(2)').attr('data-original-title', 'Switch to hexadecimal representation');
			$(this).parent().children(':nth-child(2)').attr('aria-label', 'Switch to hexadecimal representation');
		} else {
			val = val.split(' ');
			hex = '';
			val.forEach(function(entry) {
				hex += parseInt(entry , 2).toString(16).toUpperCase();
			});
			$(this).parent().children(':first-child').text(hex);
			$(this).parent().children(':first-child').attr('data-original-title', 'Hexadecimal representation');
			$(this).parent().children(':nth-child(2)').attr('data-original-title', 'Switch to binary representation');
			$(this).parent().children(':nth-child(2)').attr('aria-label', 'Switch to binary representation');
		}
	});
</script>
<?php
	echo $this->Js->writeBuffer();
?>
