<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc'] == $me['org']) || ($isAclModifyOrg && $event['Event']['orgc'] == $me['org']));
$mayPublish = ($isAclPublish && $event['Event']['orgc'] == $me['org']);
?>
<?php
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'viewEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>

<div class="events view">
	<?php
		if ('true' == Configure::read('MISP.showorg') || $isAdmin) {
			echo $this->element('img', array('id' => $event['Event']['orgc']));
			$left = true;
		}
		$title = $event['Event']['info'];
		if (strlen($title) > 55) $title = substr($title, 0, 55) . '...';
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
				<?php if ('true' == Configure::read('MISP.showorg') || $isAdmin): ?>
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
				<?php endif; ?>
				<dt>Contributors</dt>
				<dd>
					<?php 
						foreach($logEntries as $k => $entry) {
							if ('true' == Configure::read('MISP.showorg') || $isAdmin) {
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
						<dd>
						<table>
							<tr>
						<?php 
							foreach ($tags as $tag): ?>
							<td style="padding-right:0px;">
								<?php if ($isAclTagger): ?>
								<a href="/events/index/searchtag:<?php echo $tag['Tag']['id']; ?>" class=tagFirstHalf style="background-color:<?php echo $tag['Tag']['colour'];?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
								<?php else: ?>
								<a href="/events/index/searchtag:<?php echo $tag['Tag']['id']; ?>" class=tag style="background-color:<?php echo $tag['Tag']['colour'];?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
								<?php endif; ?>
							</td>
							<?php if ($isAclTagger): ?>
							<td style="padding-left:0px;padding-right:5px;">
							<?php 
							echo $this->Form->postLink('x', array('action' => 'removeTag', $event['Event']['id'], $tag['Tag']['id']), array('class' => 'tagSecondHalf', 'title' => 'Delete'), ('Are you sure you want to delete this tag?'));
							?>
							</td>
							<?php endif; ?>
							<?php 
							endforeach;
							if ($isAclTagger) : ?>
							<td id ="addTagTD" style="display:none;">
								<?php
									echo $this->Form->create('', array('action' => 'addTag', 'style' => 'margin:0px;'));
									echo $this->Form->hidden('id', array('value' => $event['Event']['id']));
									echo $this->Form->input('tag', array(
										'options' => array($allTags),
										'value' => 0,
										'label' => false,
										'style' => array('height:22px;padding:0px;margin-bottom:0px;'),
										'onChange' => 'this.form.submit()',
										'class' => 'input-large'));
									echo $this->Form->end();
								?>
							</td>
							<td>
							<button id="addTagButton" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">+</button>
					
							</td>
							<?php else:
									if (empty($tags)) echo '&nbsp;'; 
								endif; ?>
						</tr>
						</table>
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
				<dd>
					<?php echo nl2br(h($event['Event']['info'])); ?>
					&nbsp;
				</dd>
				<dt>Published</dt>
				<dd style="color: red;">
					<b><?php echo ($event['Event']['published'] == 1 ? 'Yes' : 'No');  ?></b>
					&nbsp;
				</dd>
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
	<div id="attributes_div">
		<?php
if (!empty($event['Attribute']) || !empty($remaining)):?>
		<table class="table table-striped table-condensed">
		<tr>
			<th>Date</th>
			<th>Category</th>
			<th>Type</th>
			<th>Value</th>
			<th>Comment</th>
			<th>Related Events</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>">IDS</th>
			<th title="<?php echo $attrDescriptions['distribution']['desc'];?>">Distribution</th>
			<th class="actions">Actions</th>
		</tr><?php
	foreach ($categories as $category):
		$first = 1;
		foreach ($event['Attribute'] as $attribute):
			$extra = "";
			if ($attribute['category'] != $category) continue;
			if (count($attribute['ShadowAttribute'])) $extra .= 'highlight1';
		?>
		<tr>
			<td class= "short <?php echo $extra; ?>">
			<?php 
				if (isset($attribute['timestamp'])) echo date('Y-m-d', $attribute['timestamp']);
				else echo '&nbsp';				
			?>
			</td>
			<?php if($first): ?>
			<td class= "short <?php echo $extra; ?>" title="<?php if('' != $attribute['category']) echo $categoryDefinitions[$attribute['category']]['desc'];?>">
				<?php
				if ('' == $attribute['category']) echo '(no category)';
				else echo h($attribute['category']);
				?>
			</td>
			<?php else: ?>
			<td class= "short <?php echo $extra; ?>">
				&nbsp;
			</td>
			<?php endif; ?>
			<td class="short <?php echo $extra; ?>" title="<?php echo $typeDefinitions[$attribute['type']]['desc'];?>">
				<?php echo h($attribute['type']);?>
			</td>
			<td class="showspaces <?php echo $extra; ?>"><?php $sigDisplay = $attribute['value'];
			if ('attachment' == $attribute['type'] || 'malware-sample' == $attribute['type'] ) {
				$filenameHash = explode('|', nl2br(h($attribute['value'])));
				if (strrpos($filenameHash[0], '\\')) {
					$filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
					$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
					echo h($filepath);
					echo $this->Html->link($filename, array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
				} else {
					echo $this->Html->link($filenameHash[0], array('controller' => 'attributes', 'action' => 'download', $attribute['id']));
				}
				if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
			} elseif (strpos($attribute['type'], '|') !== false) {
				$filenameHash = explode('|', $attribute['value']);
				echo h($filenameHash[0]);
				if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
			} elseif ('vulnerability' == $attribute['type']) {
				if (! is_null(Configure::read('MISP.cveurl'))) {
					$cveUrl = Configure::read('MISP.cveurl');
				} else {
					$cveUrl = "http://www.google.com/search?q=";
				}
				echo $this->Html->link(h($sigDisplay), h($cveUrl) . h($sigDisplay), array('target' => '_blank'));
			} elseif ('link' == $attribute['type']) {
				echo $this->Html->link(h($sigDisplay), h($sigDisplay));
			} else {
				$sigDisplay = str_replace("\r", '', $sigDisplay);
				echo nl2br(h($sigDisplay));
			}
				?>
			</td>
			<td class="showspaces bitwider <?php echo $extra; ?>"><?php echo h($attribute['comment']); ?></td>
			<td class="shortish <?php echo $extra; ?>">
				<?php
			$first = 0;
			?>
				<ul class="inline" style="margin:0px;">
			<?php
			if (isset($relatedAttributes[$attribute['id']]) && (null != $relatedAttributes[$attribute['id']])) {
				foreach ($relatedAttributes[$attribute['id']] as $relatedAttribute) {
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
				<td class="short <?php echo $extra; ?>"><?php echo $attribute['to_ids'] ? 'Yes' : 'No';?></td>
				<td class="short
					<?php
						echo $extra;
						if ($attribute['distribution'] == 0) echo 'privateRedText';
					?>
				">
					<?php echo $attribute['distribution'] != 3 ? $distributionLevels[$attribute['distribution']] : 'All';?>
				</td>
				<td class="short action-links
					<?php echo $extra;?>
				">
					<?php
						if ($isSiteAdmin || $mayModify) {
							echo $this->Html->link('', array('controller' => 'attributes', 'action' => 'edit', $attribute['id']), array('class' => 'icon-edit', 'title' => 'Edit'));
							echo $this->Form->postLink('', array('controller' => 'attributes', 'action' => 'delete', $attribute['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this attribute? Keep in mind that this will also delete this attribute on remote MISP instances.'));
						} else {
							echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'edit', $attribute['id']), array('class' => 'icon-edit', 'title' => 'Propose Edit'));
						}
					?>
				</td>
			</tr>
			<?php
			// Create an entry for each shadow attribute right below the attribute that it proposes to edit
			// $extra is used for extra style code added to cells that have a highlighting border around them.
			$extra = null;
			$extra = 'highlight2';
			foreach ($attribute['ShadowAttribute'] as $shadowAttribute): ?>
				<tr class="highlight2">
					<td class= "short <?php echo $extra; ?>">&nbsp</td>
					<td class="short highlight2" title="
						<?php if('' != $shadowAttribute['category']) echo $categoryDefinitions[$shadowAttribute['category']]['desc'];?>
					">
						<?php
							if ($shadowAttribute['category'] != $attribute['category']) echo h($shadowAttribute['category']);
						?>
					</td>
					<td class="short highlight2" title="
						<?php
							echo $typeDefinitions[$shadowAttribute['type']]['desc'];
						?>
					">
						<?php
							if ($shadowAttribute['type'] != $attribute['type']) echo h($shadowAttribute['type']);
						?>
					</td>
					<td class="showspaces highlight2"><?php
							if ($shadowAttribute['value'] != $attribute['value']) {
								$sigDisplay = $shadowAttribute['value'];
								if ('attachment' == $shadowAttribute['type'] || 'malware-sample' == $shadowAttribute['type'] ) {
									$filenameHash = explode('|', $shadowAttribute['value']);
									if (strrpos($filenameHash[0], '\\')) {
										$filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
										$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
										echo $filepath;
										echo $this->Html->link($filename, array('controller' => 'attributes', 'action' => 'download', $shadowAttribute['id']));
									} else {
										echo $this->Html->link($filenameHash[0], array('controller' => 'attributes', 'action' => 'download', $shadowAttribute['id']));
									}
									if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
								} elseif (strpos($shadowAttribute['type'], '|') !== false) {
									$filenameHash = explode('|', $shadowAttribute['value']);
									echo h($filenameHash[0]);
										if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
								} elseif ('vulnerability' == $shadowAttribute['type']) {
									echo $this->Html->link(h($sigDisplay), 'http://www.google.com/search?q=' . h($sigDisplay), array('target' => '_blank'));
								} elseif ('link' == $shadowAttribute['type']) {
									echo $this->Html->link(h($sigDisplay), h($sigDisplay));
								} else {
									echo nl2br(h($sigDisplay));
								}
							}
						?></td>
					<td class="short highlight2">
					<?php 
						echo h($shadowAttribute['comment']);
					?>
					</td>
					<td class="short highlight2">
					</td>
					<td class="short highlight2">
					<?php
						if ($shadowAttribute['to_ids'] != $attribute['to_ids']) echo $shadowAttribute['to_ids'] ? 'Yes' : 'No';
					?>
					</td>
					<td class="short highlight2"></td>
					<td class="short action-links highlight2">
					<?php
						if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin) {
							echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'accept', $shadowAttribute['id']), array('class' => 'icon-ok', 'title' => 'Accept'), 'Are you sure you want to accept this proposal?');
						}
						if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin || ($shadowAttribute['org'] == $me['org'])) {
							echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'discard', $shadowAttribute['id']), array('class' => 'icon-trash', 'title' => 'Discard'), 'Are you sure you want to discard this proposal?');
						}
					?>
					</td>
				</tr>
					<?php
						endforeach;
						endforeach;
						endforeach;

						// As a last step, attributes that have been proposed by users of other organisations to be added to an event are listed at the end
						$first = true;
						if (isset($remaining)):
							foreach ($remaining as $remain):
								$extra = 'highlight2';
								if ($first) {
									//$extra .= ' highlightTop';
									$first = false;
								}
								//if ($remain === end($remaining)) $extra .= ' highlightBottom';
								?>
							<tr class="highlight2">
								<td class= "short <?php echo $extra; ?>">
									<?php 
										echo '&nbsp';				
									?>
								</td>
								<td class="highlight2" title="<?php if('' != $remain['category']) echo $categoryDefinitions[$remain['category']]['desc'];?>">
								<?php
									echo h($remain['category']);
								?>
								</td>
								<td class="short highlight2" title="
									<?php
										echo $typeDefinitions[$remain['type']]['desc'];
									?>
								">
									<?php
										echo h($remain['type']);
									?>
								</td>
								<td class="showspaces highlight2"><?php
										$sigDisplay = nl2br(h($remain['value']));
										if ('attachment' == $remain['type'] || 'malware-sample' == $remain['type'] ) {
											$filenameHash = explode('|', $remain['value']);
											if (strrpos($filenameHash[0], '\\')) {
												$filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
												$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
												echo $filepath;
												echo $this->Html->link($filename, array('controller' => 'shadow_attributes', 'action' => 'download', $remain['id']));
											} else {
												echo $this->Html->link($filenameHash[0], array('controller' => 'shadow_attributes', 'action' => 'download', $remain['id']));
											}
											if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
										} elseif (strpos($remain['type'], '|') !== false) {
											$filenameHash = explode('|', $remain['value']);
											echo h($filenameHash[0]);
											if (isset($filenameHash[1])) echo ' | ' . $filenameHash[1];
										} elseif ('vulnerability' == $remain['type']) {
											echo $this->Html->link(h($sigDisplay), 'http://www.google.com/search?q=' . h($sigDisplay), array('target' => '_blank'));
										} elseif ('link' == $remain['type']) {
											echo $this->Html->link(h($sigDisplay), h($sigDisplay));
										} else {
											echo nl2br(h($sigDisplay));
										}
									?></td>
								<td class="short highlight2">
								<?php 
									echo h($remain['comment']);
								?>
								</td>
								<td class="short highlight2">
								</td>
								<td class="short highlight2">
									<?php
										echo $remain['to_ids'] ? 'Yes' : 'No';
									?></td>
									<td class="short highlight2"></td>
									<td class="short action-links highlight2">
									<?php
										if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin) {
											echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'accept', $remain['id']), array('class' => 'icon-ok', 'title' => 'Accept'), 'Are you sure you want to accept this proposal?');
										}
										if (($event['Event']['orgc'] == $me['org'] && $mayModify) || $isSiteAdmin || ($remain['org'] == $me['org'])) {
											echo $this->Form->postLink('', array('controller' => 'shadow_attributes', 'action' => 'discard', $remain['id']), array('class' => 'icon-trash', 'title' => 'Discard'), 'Are you sure you want to discard this proposal?');
										}
									?>
								</td>
							</tr>
							<?php
						endforeach;
					endif;
					?>
				</table>
				<?php
				endif; ?>
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
