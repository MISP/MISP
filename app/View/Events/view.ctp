<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc'] == $me['org']) || ($isAclModifyOrg && $event['Event']['orgc'] == $me['org']));
$mayPublish = ($isAclPublish && $event['Event']['orgc'] == $me['org']);
?>
<?php
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'viewEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>
<div class="events view">
	<?php
		if (Configure::read('MISP.showorg') || $isAdmin) {
			echo $this->element('img', array('id' => $event['Event']['orgc']));
			$left = true;
		}
		$title = $event['Event']['info'];
		if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
	?>
	<div class="row-fluid">
		<div class="span8">
			<h2><?php echo nl2br(h($title)); ?></h2>
			<dl>
				<dt>Event ID</dt>
				<dd>
					<?php echo h($event['Event']['id']); ?>
					&nbsp;
				</dd>
				<dt>Uuid</dt>
				<dd>
					<?php echo h($event['Event']['uuid']); ?>
					&nbsp;
				</dd>
				<?php 
					if (Configure::read('MISP.showorgalternate') && (Configure::read('MISP.showorg') || $isAdmin)): ?>
						<dt>Source Organisation</dt>
						<dd>
							<?php echo h($event['Event']['orgc']); ?>
							&nbsp;
						</dd>
						<dt>Member Organisation</dt>
						<dd>
							<?php echo h($event['Event']['org']); ?>
							&nbsp;
						</dd>
				<?php 	
					else:
						if (Configure::read('MISP.showorg') || $isAdmin): ?>
							<dt>Org</dt>
							<dd>
								<?php echo h($event['Event']['orgc']); ?>
								&nbsp;
							</dd>
							<?php endif; ?>
							<?php if ($isSiteAdmin): ?>
							<dt>Owner org</dt>
							<dd>
								<?php echo h($event['Event']['org']); ?>
								&nbsp;
							</dd>
				<?php 
						endif; 
					endif;
						
				?>
				<dt>Contributors</dt>
				<dd>
					<?php 
						foreach($logEntries as $k => $entry) {
							if (Configure::read('MISP.showorg') || $isAdmin) {
								?>
									<a href="/logs/event_index/<?php echo $event['Event']['id'] . '/' . h($entry['Log']['org']);?>" style="margin-right:2px;text-decoration: none;">
								<?php 
									echo $this->element('img', array('id' => $entry['Log']['org'], 'imgSize' => 24, 'imgStyle' => true));
								?>
									</a>
								<?php 
							}
						}		
					?>
					&nbsp;
				</dd>
				<?php if (isset($event['User']['email']) && ($isSiteAdmin || ($isAdmin && $me['org'] == $event['Event']['org']))): ?>
				<dt>Email</dt>
				<dd>
					<?php echo h($event['User']['email']); ?>
					&nbsp;
				</dd>
				<?php endif; ?>
				<?php 
					if (Configure::read('MISP.tagging')): ?>
						<dt>Tags</dt>
						<dd class="eventTagContainer">
							<?php echo $this->element('ajaxTags', array('event' => $event, 'tags' => $tags)); ?>
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
						if ($event['ThreatLevel']['name']) echo h($event['ThreatLevel']['name']);
						else echo h($event['Event']['threat_level_id']);
					?>
					&nbsp;
				</dd>
				<dt title="<?php echo $eventDescriptions['analysis']['desc'];?>">Analysis</dt>
				<dd>
					<?php echo h($analysisLevels[$event['Event']['analysis']]); ?>
					&nbsp;
				</dd>
				<dt>Distribution</dt>
				<dd <?php if($event['Event']['distribution'] == 0) echo 'class = "privateRedText"';?> title = "<?php echo h($distributionDescriptions[$event['Event']['distribution']]['formdesc'])?>">
					<?php 
						echo h($distributionLevels[$event['Event']['distribution']]); 
					?>
				</dd>
				<dt>Description</dt>
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

	<?php if (!empty($relatedEvents)):?>
	<div class="related span4">
		<h3>Related Events</h3>
		<ul class="inline">
			<?php foreach ($relatedEvents as $relatedEvent): ?>
			<li>
			<div title="<?php echo h($relatedEvent['Event']['info']); ?>">
			<?php
			$linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
			if ($relatedEvent['Event']['org'] == $me['org']) {
				echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']), array('style' => 'color:red;'));
			} else {
				echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']));
			}
			?>
			</div></li>
			<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>
	</div>
	<br />
	<div class="toggleButtons">
		<button class="btn btn-inverse toggle-left btn.active qet" id="pivots_active">
			<span class="icon-minus icon-white" style="vertical-align:top;"></span>Pivots
		</button>
		<button class="btn btn-inverse toggle-left qet" style="display:none;" id="pivots_inactive">
			<span class="icon-plus icon-white" style="vertical-align:top;"></span>Pivots
		</button>
		<button class="btn btn-inverse toggle qet" id="attributes_active">
			<span class="icon-minus icon-white" style="vertical-align:top;"></span>Attributes
		</button>
		<button class="btn btn-inverse toggle qet" id="attributes_inactive" style="display:none;">
			<span class="icon-plus icon-white" style="vertical-align:top;"></span>Attributes
		</button>
		<button class="btn btn-inverse toggle-right qet" id="discussions_active">
			<span class="icon-minus icon-white" style="vertical-align:top;"></span>Discussion
		</button>
		<button class="btn btn-inverse toggle-right qet" id="discussions_inactive" style="display:none;">
			<span class="icon-plus icon-white" style="vertical-align:top;"></span>Discussion
		</button>
	</div>
	<br />
	<br />
	<div id="pivots_div">
		<?php if (sizeOf($allPivots) > 1) echo $this->element('pivot'); ?>
	</div>
	<div id="attribute_creation_div" style="display:none;">
		<?php 
			echo $this->element('eventattributecreation');
		?>
	</div>
	<div id="attributes_div">
		<?php 
			echo $this->element('eventattribute');
		?>
	</div>
	<div id="discussions_div">
		<?php
			echo $this->element('eventdiscussion');
		?>
	</div>
</div>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	//loadEventTags("<?php echo $event['Event']['id']; ?>");	
	$("th, td, dt, div, span, li").tooltip({
		'placement': 'top',
		'container' : 'body',
		delay: { show: 500, hide: 100 }
		});
	$('#discussions_active').click(function() {
		  $('#discussions_div').hide();
		  $('#discussions_active').hide();
		  $('#discussions_inactive').show();
		});
	$('#discussions_inactive').click(function() {
		  $('#discussions_div').show();
		  $('#discussions_active').show();
		  $('#discussions_inactive').hide();
		});
	$('#attributes_active').click(function() {
		  $('#attributes_div').hide();
		  $('#attributes_active').hide();
		  $('#attributes_inactive').show();
		});
	$('#attributes_inactive').click(function() {
		  $('#attributes_div').show();
		  $('#attributes_active').show();
		  $('#attributes_inactive').hide();
		});
	$('#pivots_active').click(function() {
		  $('#pivots_div').hide();
		  $('#pivots_active').hide();
		  $('#pivots_inactive').show();
		});
	$('#pivots_inactive').click(function() {
		  $('#pivots_div').show();
		  $('#pivots_active').show();
		  $('#pivots_inactive').hide();
		});

	$('#addTagButton').click(function() {
		$('#addTagTD').show();
		$('#addTagButton').hide();
	});
});
</script>
