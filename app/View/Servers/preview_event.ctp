<div class="events view">
	<?php
		$title = $event['Event']['info'];
		if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
		$serverName = $server['Server']['name'] ? '"' . $server['Server']['name'] . '" (' . $server['Server']['url'] . ')' : '"' . $server['Server']['url'] . '"';
	?>
	<h4 class="visibleDL notPublished" >You are currently viewing an event on the remote instance <?php echo h($serverName); ?></h4>
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
				<dt><?php echo Configure::read('MISP.showorgalternate') ? 'Source Organisation' : 'Org'?></dt>
				<dd><?php echo h($event['Orgc']['name']); ?></dd>
				<dt><?php echo Configure::read('MISP.showorgalternate') ? 'Member Organisation' : 'Owner Org'?></dt>
				<dd><?php echo h($event['Org']['name']); ?></dd>
				<?php if (Configure::read('MISP.tagging')): ?>
					<dt>Tags</dt>
					<dd class="eventTagContainer">
					<?php if (!empty($event['Tag'])) foreach ($event['Tag'] as $tag): ?>
						<span style="padding-right:0px;">
							<span role="button" tabindex="0" aria-label="Filter the remote instance by tag: <?php echo h($tag['name']); ?>" title="Filter the remote instance on the tag: <?php echo h($tag['name']); ?>" onclick="document.location.href='/servers/previewIndex/<?php echo h($server['Server']['id']); ?>/searchtag:<?php echo h($tag['name']); ?>';" class="tagFirstHalf" style="background-color:<?php echo h($tag['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['colour']);?>"><?php echo h($tag['name']); ?></span>
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
				<dt>Distribution</dt>
				<dd <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRedText"';?> title = "<?php echo h($distributionDescriptions[$event['Event']['distribution']]['formdesc'])?>">
					<?php
						if ($event['Event']['distribution'] == 4):
					?>
							<?php echo h($event['SharingGroup']['name']); ?></a>
					<?php
						else:
							echo h($distributionLevels[$event['Event']['distribution']]);
						endif;
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
	<?php if (!empty($event['RelatedEvent'])):?>
	<div class="related span4">
		<h3>Related Events</h3>
		<ul class="inline">
			<?php foreach ($event['RelatedEvent'] as $relatedEvent):
				if (isset($relatedEvent['Event'][0])) $relatedEvent['Event'] = $relatedEvent['Event'][0];
			?>
			<li>
			<div title="<?php echo h($relatedEvent['Event']['info']); ?>">
			<a href = "<?php echo '/servers/previewEvent/' . $server['Server']['id'] . '/' . $relatedEvent['Event']['id']; ?>"><?php echo h($relatedEvent['Event']['date']) . ' (' . h($relatedEvent['Event']['id']) . ')'; ?></a>
			</div></li>
			<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>
	</div>
	<br />
	<div id="attributes_div">
		<?php echo $this->element('Servers/eventattribute'); ?>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'previewEvent', 'id' => $event['Event']['id']));
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
