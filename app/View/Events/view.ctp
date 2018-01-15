<?php
	$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
	$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
	if (Configure::read('Plugin.Sightings_enable') !== false) {
		$csv = array();
		$sightingPopover = '';
		if (isset($event['Sighting']) && !empty($event['Sighting'])) {
			$ownSightings = array();
			$orgSightings = array();
			$sparklineData = array();
			foreach ($event['Sighting'] as $sighting) {
				if (isset($sighting['org_id']) && $sighting['org_id'] == $me['org_id']) $ownSightings[] = $sighting;
				if (isset($sighting['org_id'])) {
					if (isset($orgSightings[$sighting['Organisation']['name']])) {
						$orgSightings[$sighting['Organisation']['name']]['count']++;
						if (!isset($orgSightings[$sighting['Organisation']['name']]['date']) || $orgSightings[$sighting['Organisation']['name']]['date'] < $sighting['date_sighting']) {
							$orgSightings[$sighting['Organisation']['name']]['date'] = $sighting['date_sighting'];
						}
					} else {
						$orgSightings[$sighting['Organisation']['name']]['count'] = 1;
						$orgSightings[$sighting['Organisation']['name']]['date'] = $sighting['date_sighting'];
					}
				} else {
					if (isset($orgSightings['Other organisations']['count'])) {
						$orgSightings['Other organisations']['count']++;
						if (!isset($orgSightings['Other organisations']['date']) || $orgSightings['Other organisations']['date'] < $sighting['date_sighting']) {
							$orgSightings['Other organisations']['date'] = $sighting['date_sighting'];
						}
					} else {
						$orgSightings['Other organisations']['count'] = 1;
						$orgSightings['Other organisations']['date'] = $sighting['date_sighting'];
					}
				}
			}
		}
	}
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'viewEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>
<div class="events view">
	<?php
		if (Configure::read('MISP.showorg') || $isAdmin) {
			echo $this->element('img', array('id' => $event['Orgc']['name'], 'imgSize' => '48px'));
		}
		$title = h($event['Event']['info']);
		if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
	?>
	<div class="row-fluid">
		<div class="span8">
			<h2><?php echo nl2br($title); ?></h2>
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
				<?php
					if (isset($event['User']['email']) && ($isSiteAdmin || ($isAdmin && $me['org_id'] == $event['Event']['org_id']))):
				?>
						<dt>Email</dt>
						<dd>
							<?php echo h($event['User']['email']); ?>
							&nbsp;
						</dd>
				<?php
					endif;
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
				<dt class="hidden"></dt><dd class="hidden"></dd>
				<dt class="background-red bold not-published <?php echo ($event['Event']['published'] == 0) ? '' : 'hidden'; ?>">Published</dt>
				<dd class="background-red bold not-published <?php echo ($event['Event']['published'] == 0) ? '' : 'hidden'; ?>">No</dd>
				<dt class="bold published <?php echo ($event['Event']['published'] == 0) ? 'hidden' : ''; ?>">Published</dt>
				<dd class="green bold published <?php echo ($event['Event']['published'] == 0) ? 'hidden' : ''; ?>">Yes</dd>
				<dt>#Attributes</dt>
				<dd><?php echo h($attribute_count);?></dd>
				<?php
					if (Configure::read('Plugin.Sightings_enable') !== false):
				?>
						<dt>Sightings</dt>
						<dd style="word-wrap: break-word;">
								<span id="eventSightingCount" class="bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="<?php echo $sightingPopover; ?>"><?php echo count($event['Sighting']); ?></span>
								(<span id="eventOwnSightingCount" class="green bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="<?php echo $sightingPopover; ?>"><?php echo isset($ownSightings) ? count($ownSightings) : 0; ?></span>)
								<?php if (!Configure::read('Plugin.Sightings_policy')) echo '- restricted to own organisation only.'; ?>
								<span class="icon-wrench useCursorPointer sightings_advanced_add" title="Advanced Sightings" role="button" tabindex="0" aria-label="Advanced sightings" data-object-id="<?php echo h($event['Event']['id']); ?>" data-object-context="event">&nbsp;</span>
						</dd>
						<dt>Activity</dt>
						<dd>
							<?php
								if (!empty($sightingsData['csv']['event'])) {
									echo $this->element('sparkline', array('id' => $event['Event']['id'], 'csv' => $sightingsData['csv']['event']));
								} else {
									echo '&nbsp';
								}
							?>
						</dd>
				<?php
					endif;
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
				<?php
					if (!Configure::read('MISP.completely_disable_correlation') && Configure::read('MISP.allow_disabling_correlation')):
				?>
						<dt <?php echo $event['Event']['disable_correlation'] ? 'class="background-red bold"' : '';?>>Correlation</dt>
						<dd <?php echo $event['Event']['disable_correlation'] ? 'class="background-red bold"' : '';?>>
								<?php
									if ($mayModify || $isSiteAdmin):
								 		if ($event['Event']['disable_correlation']):
								?>
											Disabled (<a onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'events', 'toggleCorrelation', '', '#confirmation_box');" style="color:white;cursor:pointer;font-weight:normal;">enable</a>)
								<?php
										else:
								?>
											Enabled (<a onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'events', 'toggleCorrelation', '', '#confirmation_box');" style="cursor:pointer;font-weight:normal;">disable</a>)
								<?php
										endif;
									else:
										if ($event['Event']['disable_correlation']):
											echo 'Disabled';
										else:
											echo 'Enabled';
										endif;
									endif;
								?>
						</dd>
				<?php
					endif;
				?>
			</dl>
		</div>
		<div class="related span4">
			<?php
				if (!empty($event['RelatedEvent'])):
			?>
					<h3>Related Events</h3>
					<span class="inline">
						<?php
							$count = 0;
							$total = count($event['RelatedEvent']);
							foreach ($event['RelatedEvent'] as $relatedEvent):
								$count++;
								$relatedData = array('Orgc' => $relatedEvent['Event']['Orgc']['name'], 'Date' => $relatedEvent['Event']['date'], 'Info' => $relatedEvent['Event']['info']);
								$popover = '';
								foreach ($relatedData as $k => $v) {
									$popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
								}
								if ($count == 11 && $total > 10):
									?>
										<div class="no-side-padding correlation-expand-button useCursorPointer linkButton blue">Show (<?php echo $total - $count; ?>) more</div>
									<?php
								endif;
						?>
								<span data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover" class="<?php if ($count > 11) echo 'correlation-expanded-area'; ?>" style="white-space: nowrap;<?php echo ($count > 10) ? 'display:none;' : ''; ?>">
						<?php
								$linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
								if ($relatedEvent['Event']['orgc_id'] == $me['org_id']) {
									echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']), array('style' => 'color:red;'));
								} else {
									echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']));
								}
						?>
								</span>&nbsp;
						<?php
							endforeach;
							if ($total > 10):
						?>
							<div class="no-side-padding correlation-collapse-button useCursorPointer linkButton blue" style="display:none;">Collapse...</div>
						<?php
							endif;
						?>
					</span>
			<?php
				endif;
				if (!empty($event['Feed']) || !empty($event['Event']['FeedCount'])):
			?>
					<h3>Related Feeds</h3>
			<?php
					if (!empty($event['Feed'])):
						foreach ($event['Feed'] as $relatedFeed):
							$relatedData = array('Name' => $relatedFeed['name'], 'URL' => $relatedFeed['url'], 'Provider' => $relatedFeed['provider'], 'Source Format' => $relatedFeed['source_format']);
							$popover = '';
							foreach ($relatedData as $k => $v) {
								$popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
							}
				?>
								<span data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover" style="white-space: nowrap;">
									<?php
										if ($relatedFeed ['source_format'] == 'misp'):
									?>
											<form action="<?php echo $baseurl; ?>/feeds/previewIndex/<?php echo h($relatedFeed['id']); ?>" method="post" style="margin:0px;">
												<input type="hidden" name="data[Feed][eventid]" value="<?php echo h(json_encode($relatedFeed['event_uuids'], true)); ?>">
												<input type="submit" class="linkButton useCursorPointer" value="<?php echo h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'; ?>" />
											</form>
									<?php
										else:
									?>
											<a href="<?php echo $baseurl; ?>/feeds/previewIndex/<?php echo h($relatedFeed['id']); ?>"><?php echo h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'; ?></a><br />
									<?php
										endif;
									?>
								</span>
				<?php
						endforeach;
					elseif (!empty($event['Event']['FeedCount'])):
				?>
						<span>
							This event has <span class="bold"><?php echo h($event['Event']['FeedCount']); ?></span>
							correlations with data contained within the various feeds, however, due to the large number of
							attributes the actual feed correlations are not shown. Click (<a href="<?php echo h($this->here); ?>/overrideLimit:1">here</a>)
							to refresh the page with the feed data loaded.
					 </span>
				<?php
					endif;
				endif;
			?>
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
	</div>
	<br />
	<div class="toggleButtons">
		<button class="btn btn-inverse toggle-left btn.active qet galaxy-toggle-button" id="pivots_toggle" data-toggle-type="pivots">
			<span class="icon-minus icon-white" title="Toggle pivot graph" role="button" tabindex="0" aria-label="Toggle pivot graph" style="vertical-align:top;"></span>Pivots
		</button>
		<button class="btn btn-inverse toggle qet galaxy-toggle-button" id="galaxies_toggle" data-toggle-type="galaxies">
			<span class="icon-minus icon-white" title="Toggle galaxies" role="button" tabindex="0" aria-label="Toggle galaxies" style="vertical-align:top;"></span>Galaxy
		</button>
		<button class="btn btn-inverse toggle qet galaxy-toggle-button" id="attributes_toggle" data-toggle-type="attributes">
			<span class="icon-minus icon-white" title="Toggle attributes" role="button" tabindex="0" aria-label="Toggle attributes" style="vertical-align:top;"></span>Attributes
		</button>
		<button class="btn btn-inverse toggle-right qet galaxy-toggle-button" id="discussions_toggle" data-toggle-type="discussions">
			<span class="icon-minus icon-white" title="Toggle discussions" role="button" tabindex="0" aria-label="Toggle discussions" style="vertical-align:top;"></span>Discussion
		</button>
	</div>
	<br />
	<br />
	<div id="pivots_div">
		<?php if (sizeOf($allPivots) > 1) echo $this->element('pivot'); ?>
	</div>
	<div id="galaxies_div" class="info_container">
		<h4 class="blue">Galaxies</h4>
		<?php echo $this->element('galaxyQuickView', array('mayModify' => $mayModify, 'isAclTagger' => $isAclTagger)); ?>
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
var showContext = false;
$(document).ready(function () {
	popoverStartup();

	$("th, td, dt, div, span, li").tooltip({
		'placement': 'top',
		'container' : 'body',
		delay: { show: 500, hide: 100 }
	});

	$.get("/threads/view/<?php echo $event['Event']['id']; ?>/true", function(data) {
		$("#discussions_div").html(data);
	});
});
</script>
