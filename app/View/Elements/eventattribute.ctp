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
	$fieldCount = 9;
	if (Configure::read('Plugin.Sightings_enable') !== false) {
		$fieldCount += 2;
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
	$filtered = false;
	if(isset($passedArgsArray)){
		if (count($passedArgsArray) > 0) {
			$filtered = true;
		}
	}
?>
	<div class="pagination">
		<ul>
		<?php
			$params = $this->request->named;
			unset($params['focus']);
			$url = array_merge(array('controller' => 'events', 'action' => 'viewEventAttributes', $event['Event']['id']), $params);
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
		<div id="filter_all" title="Show all attributes" role="button" tabindex="0" aria-label="Show all attributes" class="attribute_filter_text<?php if ($attributeFilter == 'all') echo '_active'; ?>" onClick="filterAttributes('all', '<?php echo h($event['Event']['id']); ?>');">All</div>
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
		<div title="input filter" tabindex="0" aria-label="input filter" class="attribute_filter_text" style="padding-top:0px;">
			<input type="text" id="attributesFilterField" style="height:20px;padding:0px;margin:0px;" class="form-control" data-eventid="<?php echo h($event['Event']['id']); ?>"></input>
				<span id="attributesFilterButton" role="button" class="icon-search" tabindex="0" aria-label="Filter on attributes value" onClick="filterAttributes('value', '<?php echo h($event['Event']['id']); ?>');"></span>
				<?php if ($filtered):?>
					<span tabindex="0" aria-label="Show all attributes" title="Remove filters" role="button" onClick="filterAttributes('all', '<?php echo h($event['Event']['id']); ?>');" class='icon-remove'></span>
				<?php endif;?>
		</div>
	</div>

	<table class="table table-striped table-condensed">
		<tr>
			<?php
				if ($mayModify && !empty($event['objects'])):
					$fieldCount += 1;
			?>
					<th><input class="select_all" type="checkbox" title="Select all" role="button" tabindex="0" aria-label="Select all attributes/proposals on current page" onClick="toggleAllAttributeCheckboxes();" /></th>
			<?php
				endif;
			?>
			<th class="context hidden"><?php echo $this->Paginator->sort('id');?></th>
			<th class="context hidden">UUID</th>
			<th><?php echo $this->Paginator->sort('timestamp', 'Date');?></th>
			<th><?php echo $this->Paginator->sort('Org.name', 'Org'); ?>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th>Tags</th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<th>Correlate</th>
			<th>Related Events</th>
			<th>Feed hits</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
			<th title="<?php echo $attrDescriptions['distribution']['desc'];?>"><?php echo $this->Paginator->sort('distribution');?></th>
			<?php
				if (Configure::read('Plugin.Sightings_enable') !== false):
					$fieldCount += 2;
			?>
					<th>Sightings</th>
					<th>Activity</th>
			<?php
				endif;
			?>
			<th class="actions">Actions</th>
		</tr>
		<?php
			$elements = array(
				0 => 'attribute',
				1 => 'proposal',
				2 => 'proposal_delete',
				3 => 'object'
			);
			$focusedRow = false;
			foreach ($event['objects'] as $k => $object) {
				$insertBlank = false;
				echo $this->element('/Events/View/row_' . $object['objectType'], array(
					'object' => $object,
					'k' => $k,
					'mayModify' => $mayModify,
					'mayChangeCorrelation' => $mayChangeCorrelation,
					'page' => $page,
					'fieldCount' => $fieldCount
				));
				if (!empty($focus) && ($object['objectType'] == 'object' || $object['objectType'] == 'attribute') && $object['uuid'] == $focus) {
					$focusedRow = $k;
				}
				if (
					($object['objectType'] == 'attribute' && !empty($object['ShadowAttribute'])) ||
					$object['objectType'] == 'object'
				):
		?>
					<tr class="blank_table_row"><td colspan="<?php echo $fieldCount; ?>"></td></tr>
		<?php
				endif;
			}
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
		<?php
			if ($focusedRow !== false):
		?>
			//window.location.hash = '.row_' + '<?php echo h($focusedRow); ?>';
			console.log('.row_' + '<?php echo h($focusedRow); ?>');
			//$.scrollTo('#row_' + '<?php echo h($k); ?>', 800, {easing:'elasout'});
			//$('html,body').animate({scrollTop: $('#row_' + '<?php echo h($k); ?>').offset().top}, 'slow');
				$('.row_' + '<?php echo h($focusedRow); ?>').focus();
		<?php
			endif;
		?>
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
	$('#attributesFilterField').bind("keydown", function(e) {
		var eventid = $('#attributesFilterField').data("eventid");
		if ((e.keyCode == 13 || e.keyCode == 10)) {
			filterAttributes('value', eventid);
		}
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
