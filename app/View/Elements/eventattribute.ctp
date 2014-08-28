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
	<ul style="margin-right:20px;">
		<?php if ($page == 1) : ?>
			<li class="prev"><span>« previous</span></li>
		<?php else: ?>
			<li class="prev"><a href="" id = "aprev">« previous</a></li>
		<?php endif; 
		for ($i = 1; $i < (1+$pageCount); $i++): 
			if ($page != $i):
		?>
				<li><a href="" id = "apage<?php echo $i; ?>" data-page-value="<?php echo $i; ?>"><?php echo $i; ?></a></li>
		<?php
			else:
		?>
				<li><span id = "apageCurrent"><?php echo $i; ?></span></li>
		<?php 
			endif;
		endfor;
		if ($page >= $pageCount): ?>
			<li class="next"><span>next »</span></li>
		<?php else: ?>
			<li class="next"><a href="" id = "anext">next »</a></li>
		<?php endif; 
		if ($page == 'all'): ?>
			<li class="all"><span>View All</span></li>
		<?php else: ?>
			<li class="all"><a href="" id = "aall">View All</a></li>
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
		echo $this->Form->input('ids', array(
			'type' => 'text',
			'value' => 'test',
			'style' => 'display:none;',
			'label' => false,
		)); 
		echo $this->Form->end();
	?>
</div>
<div id="attributeList" class="attributeListContainer">
	<div class="tabMenu tabMenuEditBlock noPrint">
		<span id="create-button" title="Add attribute" class="icon-plus useCursorPointer" onClick="clickCreateButton(<?php echo $event['Event']['id']; ?>, '<?php echo $possibleAction; ?>');"></span>
		<span id="multi-edit-button" title="Edit selected" class="icon-edit mass-select useCursorPointer" onClick="editSelectedAttributes(<?php echo $event['Event']['id']; ?>);"></span>
		<span id="multi-delete-button" title="Delete selected" class = "icon-trash mass-select useCursorPointer" onClick="deleteSelectedAttributes(<?php echo $event['Event']['id']; ?>);"></span>
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
				echo $this->element('eventattributerow', array('object' => $object, 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
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
			<li class="prev"><a href="" id = "bprev">« previous</a></li>
		<?php endif; 
		for ($i = 1; $i < (1+$pageCount); $i++): 
			if ($page != $i):
		?>
				<li><a href="" id = "bpage<?php echo $i; ?>" data-page-value="<?php echo $i; ?>"><?php echo $i; ?></a></li>
		<?php
			else:
		?>
				<li><span id = "bpageCurrent"><?php echo $i; ?></span></li>
		<?php 
			endif;
		endfor;
		if ($page >= $pageCount): ?>
			<li class="next"><span>next »</span></li>
		<?php else: ?>
			<li class="next"><a href="" id = "bnext">next »</a></li>
		<?php endif; 
		if ($page == 'all'): ?>
			<li class="all"><span>View All</span></li>
		<?php else: ?>
			<li class="all"><a href="" id = "ball">View All</a></li>
		<?php endif; ?>
	</ul>
</div>
<?php 
	for ($j = 0; $j < 2; $j++) {
		$side = 'a';
		if ($j == 1) $side = 'b'; 
		if ($page < $pageCount) {
			$this->Js->get('#' . $side . 'next')->event(
					'click',
					$this->Js->request(
						array('action' => 'view', $event['Event']['id'], 'attributesPage:' . ($page+1)),
						array(
							'update' => '#attributes_div',
							'before' => '$(".loading").show();',
							'complete' => '$(".loading").hide();',
						)
					)
			);
		}
		for ($i = 1; $i < (1+$pageCount); $i++) {
			$this->Js->get('#' . $side . 'page' . $i)->event(
					'click',
					$this->Js->request(
							array('action' => 'view', $event['Event']['id'], 'attributesPage:' . $i),
							array(
								'update' => '#attributes_div',
								'before' => '$(".loading").show();',
								'complete' => '$(".loading").hide();',
							)
					)
			);
		}
		if ($page > 1) {
			$this->Js->get('#' . $side . 'prev')->event(
					'click',
					$this->Js->request(
							array('action' => 'view', $event['Event']['id'], 'attributesPage:' . ($page-1)),
							array(
								'update' => '#attributes_div',
								'before' => '$(".loading").show();',
								'complete' => '$(".loading").hide();',
							)
					)
			);
		}
			$this->Js->get('#' . $side . 'all')->event(
					'click',
					$this->Js->request(
							array('action' => 'view', $event['Event']['id'], 'attributesPage:all'),
							array(
									'update' => '#attributes_div',
									'before' => '$(".loading").show();',
									'complete' => '$(".loading").hide();',
							)
					)
			);
	}
	endif; 
?>
<script type="text/javascript">
	$(document).ready(function(){
		$('input:checkbox').removeAttr('checked');
		$('.mass-select').hide();
		$('input[type="checkbox"]').click(function(){
			attributeListAnyCheckBoxesChecked();
		});
	});
</script>
<?php 
	echo $this->Js->writeBuffer();
?>