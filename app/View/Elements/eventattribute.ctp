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
			echo $this->element('eventattributerow', array('object' => $object));
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
	endif; 
	echo $this->Js->writeBuffer();
?>