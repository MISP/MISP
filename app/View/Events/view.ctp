<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
	if (Configure::read('Plugin.Sightings_enable')) {
		$sightingPopover = '';
		if (isset($event['Sighting']) && !empty($event['Sighting'])) {
			$ownSightings = array();
			$orgSightings = array();
			foreach ($event['Sighting'] as $sighting) {
				if (isset($sighting['org_id']) && $sighting['org_id'] == $me['org_id']) $ownSightings[] = $sighting;
				if (isset($sighting['org_id'])) {
					if (isset($orgSightings[$sighting['Organisation']['name']])) $orgSightings[$sighting['Organisation']['name']]++;
					else $orgSightings[$sighting['Organisation']['name']] = 1;
				} else {
					if (isset($orgSightings['Other organisations'])) $orgSightings['Other organisations']++;
					else $orgSightings['Other organisations'] = 1;
				}
			}
			foreach ($orgSightings as $org => $sightingCount) $sightingPopover .= '<span class=\'bold\'>' . h($org) . '</span>: <span class=\'green\'>' . h($sightingCount) . '</span><br />';
		}
	}
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'viewEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>
<div class="events view">
	<?php
		if (Configure::read('MISP.showorg') || $isAdmin) {
			echo $this->element('img', array('id' => $event['Orgc']['name']));
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
							<a href="/organisations/view/<?php echo h($event['Orgc']['id']); ?>"><?php echo h($event['Orgc']['name']); ?></a>
							&nbsp;
						</dd>
						<dt>Member Organisation</dt>
						<dd>
							<a href="/organisations/view/<?php echo h($event['Org']['id']); ?>"><?php echo h($event['Org']['name']); ?></a>
							&nbsp;
						</dd>
				<?php
					else:
						if (Configure::read('MISP.showorg') || $isAdmin): ?>
							<dt>Org</dt>
							<dd>
								<a href="/organisations/view/<?php echo h($event['Orgc']['id']); ?>"><?php echo h($event['Orgc']['name']); ?></a>
								&nbsp;
							</dd>
							<?php endif; ?>
							<?php if ($isSiteAdmin): ?>
							<dt>Owner org</dt>
							<dd>
								<a href="/organisations/view/<?php echo h($event['Org']['id']); ?>"><?php echo h($event['Org']['name']); ?></a>
								&nbsp;
							</dd>
				<?php
						endif;
					endif;

				?>
				<dt>Contributors</dt>
				<dd>
					<?php
						foreach ($contributors as $k => $entry) {
							if (Configure::read('MISP.showorg') || $isAdmin) {
								?>
									<a href="<?php echo $baseurl."/logs/event_index/".$event['Event']['id'].'/'.h($entry);?>" style="margin-right:2px;text-decoration: none;">
								<?php
									echo $this->element('img', array('id' => $entry, 'imgSize' => 24, 'imgStyle' => true));
								?>
									</a>
								<?php
							}
						}
					?>
					&nbsp;
				</dd>
				<?php if (isset($event['User']['email']) && ($isSiteAdmin || ($isAdmin && $me['org_id'] == $event['Event']['org_id']))): ?>
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
							<?php echo $this->element('ajaxTags', array('event' => $event, 'tags' => $event['EventTag'], 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id']) )); ?>
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
				<dd <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRedText"';?> title = "<?php echo h($distributionDescriptions[$event['Event']['distribution']]['formdesc'])?>">
					<?php
						if ($event['Event']['distribution'] == 4):
					?>
							<a href="/sharing_groups/view/<?php echo h($event['SharingGroup']['id']); ?>"><?php echo h($event['SharingGroup']['name']); ?></a>
					<?php
						else:
							echo h($distributionLevels[$event['Event']['distribution']]);
						endif;
					?>
				</dd>
				<dt>Info</dt>
				<dd style="word-wrap: break-word;">
					<?php echo nl2br(h($event['Event']['info'])); ?>
					&nbsp;
				</dd>
				<dt class="<?php echo ($event['Event']['published'] == 0) ? (($isAclPublish && $me['org_id'] == $event['Event']['orgc_id']) ? 'background-red bold' : 'bold') : 'bold'; ?>">Published</dt>
				<dd class="<?php echo ($event['Event']['published'] == 0) ? (($isAclPublish && $me['org_id'] == $event['Event']['orgc_id']) ? 'background-red bold' : 'red bold') : 'green bold'; ?>"><?php echo ($event['Event']['published'] == 0) ? 'No' : 'Yes'; ?></dd>
				<?php if (Configure::read('Plugin.Sightings_enable')): ?>
				<dt>Sightings</dt>
				<dd style="word-wrap: break-word;">
						<span id="eventSightingCount" class="bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="<?php echo $sightingPopover; ?>"><?php echo count($event['Sighting']); ?></span>
						(<span id="eventOwnSightingCount" class="green bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="<?php echo $sightingPopover; ?>"><?php echo isset($ownSightings) ? count($ownSightings) : 0; ?></span>)
						<?php if (!Configure::read('Plugin.Sightings_policy')) echo '- restricted to own organisation only.'; ?>
				</dd>
				<?php endif;
					if (!empty($delegationRequest)):
						if ($isSiteAdmin || $me['org_id'] == $delegationRequest['EventDelegation']['org_id']) {
							$target = $isSiteAdmin ? $delegationRequest['Org']['name'] : 'you';
							$subject = $delegationRequest['RequesterOrg']['name'] . ' has';
						} else {
							$target = $delegationRequest['Org']['name'];
							$subject = 'You have';
						}
				?>
					<dt class="background-red bold">Delegation request</dt>
					<dd class="background-red bold"><?php echo h($subject);?> requested that <?php echo h($target)?> take over this event. (<a href="#" style="color:white;" onClick="genericPopup('<?php echo $baseurl;?>/eventDelegations/view/<?php echo h($delegationRequest['EventDelegation']['id']);?>', '#confirmation_box');">View request details</a>)</dd>
				<?php endif;?>
			</dl>
		</div>
	<?php if (!empty($event['RelatedEvent'])):?>
	<div class="related span4">
		<h3>Related Events</h3>
		<ul class="inline">
			<?php foreach ($event['RelatedEvent'] as $relatedEvent): ?>
			<li>
			<?php
			$relatedData = array('Orgc' => $relatedEvent['Orgc']['name'], 'Date' => $relatedEvent['Event']['date'], 'Info' => $relatedEvent['Event']['info']);
			$popover = '';
			foreach ($relatedData as $k => $v) {
				$popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
			}
			?>
			<div data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover">
			<?php
			$linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
			if ($relatedEvent['Event']['org_id'] == $me['org_id']) {
				echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']), array('style' => 'color:red;'));
			} else {
				echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']));
			}
			?>
			</div></li>
			<?php endforeach; ?>
		</ul>
		<?php if (!empty($event['Event']['warnings'])): ?>
			<div class="warning_container" style="width:80%;">
				<h4 class="red">Warning: Potential false positives</h4>
				<?php
					$total = count($event['Event']['warnings']);
					$current = 1;
					foreach ($event['Event']['warnings'] as $id => $name) {
						echo '<a href="' . $baseurl . '/warninglists/view/' . $id . '">' . h($name) . '</a>' . ($current == $total ? '' : '<br />');
						$current++;
					}
				?>
			</div>
		<?php endif; ?>
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
	<div id="attributes_div">
		<?php echo $this->element('eventattribute'); ?>
	</div>
	<div id="discussions_div">
	</div>
	<div id="attribute_creation_div" style="display:none;">
	</div>
</div>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	popoverStartup();
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

//	$.get("/events/viewEventAttributes/<?php echo $event['Event']['id']; ?>", function(data) {
//		$("#attributes_div").html(data);
//	});
	$.get("/threads/view/<?php echo $event['Event']['id']; ?>/true", function(data) {
		$("#discussions_div").html(data);
	});
});
</script>
