<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc'] == $me['org']) || ($isAclModifyOrg && $event['Event']['orgc'] == $me['org']));
	$mayPublish = ($isAclPublish && $event['Event']['orgc'] == $me['org']);
	if (!empty($eventArray)):
	$pageCount = intval($objectCount / 50);
	if ($objectCount%50 != 0) $pageCount++;
	if ($pageCount > 1):
?>
<div class="pagination">
	<ul>
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
		<?php endif; ?>
	<ul style="margin-left:20px;">
		<?php if ($page == 'all'): ?>
			<li class="all"><span>View All</span></li>
		<?php else: ?>
			<li class="all"><a href="" id = "aall">View All</a></li>
		<?php endif; ?>
	</ul>
	</ul>
</div>
<?php 
	endif;
?>
<table class="table table-striped table-condensed">
	<tr>
		<th style="width:0px;padding:0px;border:0px;"></th>
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
			if ($object['objectType'] == 0 ) {
				if ($object['hasChildren'] == 1) $extra = 'highlight1';
			} else $extra = 'highlight2';
			if ($object['objectType'] == 1) $extra2 = '1';
	?>
	<tr>
		<td style="width: <?php echo $extra2; ?>0px;padding:0px;border:0px;"></td>
		<td class="short <?php echo $extra; ?>">
		<?php 
			if (isset($object['timestamp'])) echo date('Y-m-d', $object['timestamp']);
			else echo '&nbsp';				
		?>
		</td>
		<td class="short <?php echo $extra; ?>">
			<?php 
				echo h($object['category']);
			?>
		</td>
		<td class="short <?php echo $extra; ?>">
			<?php 
				echo h($object['type']);
			?>
		</td>
		<td class="showspaces <?php echo $extra; ?>">
			<?php 
				echo h($object['value']);
			?>
		</td>
		<td class="showspaces bitwider <?php echo $extra; ?>">
			<?php 
				echo h($object['comment']);
			?>
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
				if ($object['to_ids']) echo 'Yes';
				else echo 'No';
			?>
		</td>
		<td class="short <?php echo $extra; ?>">
			<?php 
				if ($object['objectType'] != 1 && $object['objectType'] != 2) echo h($object['distribution']);
				else echo '&nbsp';
			?>
		</td>
		<td class="short action-links <?php echo $extra;?>">
			<?php
				if ($object['objectType'] == 0) {
					if ($isSiteAdmin || $mayModify) {
						echo $this->Html->link('', array('controller' => 'attributes', 'action' => 'edit', $object['id']), array('class' => 'icon-edit', 'title' => 'Edit'));
						echo $this->Form->postLink('', array('controller' => 'attributes', 'action' => 'delete', $object['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this attribute? Keep in mind that this will also delete this attribute on remote MISP instances.'));
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
			<?php 
		endforeach;
	?>
</table>
<?php if ($pageCount > 1): ?>
<span id = "current_page" style="visibility:hidden;"><?php echo $page;?></span>
<p>Page <?php echo $page; ?> of <?php echo $pageCount;?>, showing <?php echo count($eventArray); ?> records out of <?php echo $objectCount; ?> total, starting on <?php echo (($page-1) * 50) + 1;?>, ending on <?php echo (($page-1) * 50) + count($eventArray); ?></p>
<div class="pagination">
	<ul>
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
				<li><span id = "apageCurrent"><?php echo $i; ?></span></li>
		<?php 
			endif;
		endfor;
		if ($page >= $pageCount): ?>
			<li class="next"><span>next »</span></li>
		<?php else: ?>
			<li class="next"><a href="" id = "bnext">next »</a></li>
		<?php endif; ?>
	</ul>
	<ul style="margin-left:20px;">
		<?php if ($page == 'all'): ?>
			<li class="all"><span>View All</span></li>
		<?php else: ?>
			<li class="all"><a href="" id = "ball">View All</a></li>
		<?php endif; ?>
	</ul>
</div>
<?php
	endif; 
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
?>
<script>
function deleteObject(type, id) {
	$.ajax({
		success:function (data, textStatus) {
			updateAttributeIndexOnSuccess();
		}, 
		type:"post", 
		url:"/" + type + "/delete/" + id,
	});
}

function updateAttributeIndexOnSuccess() {
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		success:function (data, textStatus) {
			$(".loading").hide();
			$("#attributes_div").html(data);
		}, 
		url:"/events/view/<?php echo $event['Event']['id']; ?>/attributesPage:1",
	});
}
</script>
<?php
	endif; 
	echo $this->Js->writeBuffer();
?>