<div class="events view">
	<?php
		$title = $event['Event']['info'];
		if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
	?>
	<h4 class="visibleDL notPublished" >You are currently viewing an event from a feed (<?php echo h($feed['Feed']['name']); ?> by <?php echo h($feed['Feed']['provider']); ?>)</h4>
	<div class="row-fluid">
		<div class="span8">
			<h2><?php echo nl2br(h($title)); ?></h2>
			<dl>
				<dt>Uuid</dt>
				<dd><?php echo h($event['Event']['uuid']); ?></dd>
				<dt><?php echo Configure::read('MISP.showorgalternate') ? 'Source Organisation' : 'Org'?></dt>
				<dd><?php echo h($event['Orgc']['name']); ?></dd>
				<?php if (Configure::read('MISP.tagging')): ?>
					<dt>Tags</dt>
					<dd class="eventTagContainer">
					<?php if (!empty($event['Tag'])) foreach ($event['Tag'] as $tag): ?>
						<span style="padding-right:0px;">
							<span class="tagFirstHalf" style="background-color:<?php echo isset($tag['colour']) ? h($tag['colour']) : 'red';?>;color:<?php echo $this->TextColour->getTextColour(isset($tag['colour']) ? h($tag['colour']) : 'red'); ?>"><?php echo h($tag['name']); ?></span>
						</span>
					<?php endforeach; ?>&nbsp;
					</dd>
				<?php endif; ?>
				<dt>Date</dt>
				<dd>
					<?php echo h($event['Event']['date']); ?>
					&nbsp;
				</dd>
				<dt title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>">Threat Level</dt>
				<dd>
					<?php
						echo h($threatLevels[$event['Event']['threat_level_id']]);
					?>
					&nbsp;
				</dd>
				<dt title="<?php echo $eventDescriptions['analysis']['desc'];?>">Analysis</dt>
				<dd>
					<?php echo h($analysisLevels[$event['Event']['analysis']]); ?>
					&nbsp;
				</dd>
				<dt>Info</dt>
				<dd style="word-wrap: break-word;">
					<?php echo nl2br(h($event['Event']['info'])); ?>
					&nbsp;
				</dd>
				<?php
					$published = '';
					$notPublished = 'style="display:none;"';
					if ($event['Event']['published'] == 0) {
						$published = 'style="display:none;"';
						$notPublished = '';
					}
				?>
						<dt class="published" <?php echo $published;?>>Published</dt>
						<dd class="published green" <?php echo $published;?>>Yes</dd>
				<?php
					if ($isAclPublish) :
				?>
						<dt class="visibleDL notPublished" <?php echo $notPublished;?>>Published</dt>
						<dd class="visibleDL notPublished" <?php echo $notPublished;?>>No</dd>
				<?php
					else:
				?>
						<dt class="notPublished" <?php echo $notPublished;?>>Published</dt>
						<dd class="notPublished red" <?php echo $notPublished;?>>No</dd>
				<?php endif; ?>
			</dl>
		</div>

	<?php if (!empty($event['RelatedEvent'])):?>
	<div class="related span4">
		<h3>Related Events</h3>
		<ul class="inline">
			<?php foreach ($event['RelatedEvent'] as $relatedEvent): ?>
			<li>
			<div title="<?php echo h($relatedEvent['Event'][0]['info']); ?>">
			<a href = "<?php echo '/servers/previewEvent/' . $server['Server']['id'] . '/' . $relatedEvent['Event'][0]['id']; ?>"><?php echo h($relatedEvent['Event'][0]['date']) . ' (' . h($relatedEvent['Event'][0]['id']) . ')'; ?></a>
			</div></li>
			<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>
	</div>
	<br />
	<div id="attributes_div">
		<?php
			$all = false;
			if (isset($this->params->params['paging']['Event']['page']) && $this->params->params['paging']['Event']['page'] == 0) $all = true;
		?>
		<div class="pagination">
	        <ul>
	        <?php
		        $this->Paginator->options(array(
					'url' => array($feed['Feed']['id'], $event['Event']['uuid']),
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
	    <div id="attributeList" class="attributeListContainer">
			<table class="table table-striped table-condensed">
				<tr>
					<th><?php echo $this->Paginator->sort('date');?></th>
					<th><?php echo $this->Paginator->sort('category');?></th>
					<th><?php echo $this->Paginator->sort('type');?></th>
					<th><?php echo $this->Paginator->sort('value');?></th>
					<th><?php echo $this->Paginator->sort('comment');?></th>
					<th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
				</tr>
			    <?php
					foreach ($event['objects'] as $k => $object):
				?>
					<tr id = "<?php echo 'Attribute_' . $object['uuid'] . '_tr'; ?>">
						<td class="short"><?php echo (isset($object['timestamp'])) ? date('Y-m-d', $object['timestamp']) : '&nbsp'; ?></td>
						<td class="shortish"><?php echo h($object['category']); ?></td>
						<td class="shortish"><?php echo h($object['type']); ?></td>
						<td class="shortish"><?php echo h($object['value']); ?></td>
						<td class="shortish"><?php echo h($object['comment']); ?></td>
						<td class="shortish"><?php echo ($object['to_ids']) ? 'Yes' : 'No'; ?></td>
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
					'url' => array($feed['Feed']['id'], $event['Event']['uuid']),
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
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'previewEvent', 'id' => $event['Event']['uuid']));
?>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	//loadEventTags("<?php echo $event['Event']['id']; ?>");
	$("th, td, dt, div, span, li").tooltip({
		'placement': 'top',
		'container' : 'body',
		delay: { show: 500, hide: 100 }
		});
});
</script>
