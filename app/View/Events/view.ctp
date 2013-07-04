<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['orgc'] == $me['org']));
$mayPublish = ($isAclPublish && $event['Event']['orgc'] == $me['org']);
?>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li class="active"><a href="/events/view/<?php echo $event['Event']['id'];?>">View Event</a></li>
		<li><a href="/logs/event_index/<?php echo $event['Event']['id'];?>">View Event History</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><a href="/events/edit/<?php echo $event['Event']['id'];?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $event['Event']['id'];?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $event['Event']['id'];?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $event['Event']['id'];?>">Populate from IOC</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $event['Event']['id'];?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $event['Event']['id'];?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<?php if ( 0 == $event['Event']['published'] && ($isAdmin || $mayPublish)): ?>
		<li><?php echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?'); ?></li>
		<li><?php echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $event['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!'); ?></li>
		<?php else: ?>
		<!-- ul><li>Alert already sent</li></ul -->
		<?php endif; ?>
		<li><a href="/events/contact/<?php echo $event['Event']['id'];?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $event['Event']['id'];?>">Download as XML</a></li>
		<?php if ($event['Event']['published']): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $event['Event']['id'];?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $event['Event']['id'];?>">Download as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>


<div class="events view">

	<?php
	if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin) {
		echo $this->element('img', array('id' => $event['Event']['orgc']));
	}
	?>
	<div class="row-fluid">
		<div class="span8">
			<h2>Event</h2>
			<dl>
				<dt>ID</dt>
				<dd>
					<?php echo h($event['Event']['id']); ?>
					&nbsp;
				</dd>
				<dt>Uuid</dt>
				<dd>
					<?php echo h($event['Event']['uuid']); ?>
					&nbsp;
				</dd>
				<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
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
				<?php if ($isSiteAdmin || ($isAdmin && $me['org'] == $event['Event']['org'])): ?>
				<dt>Email</dt>
				<dd>
					<?php echo h($event['User']['email']); ?>
					&nbsp;
				</dd>
				<?php endif; ?>
				<dt>Date</dt>
				<dd>
					<?php echo h($event['Event']['date']); ?>
					&nbsp;
				</dd>
				<dt title="<?php echo $eventDescriptions['risk']['desc'];?>">Risk</dt>
				<dd>
					<?php echo h($event['Event']['risk']); ?>
					&nbsp;
				</dd>
				<dt title="<?php echo $eventDescriptions['analysis']['desc'];?>">Analysis</dt>
				<dd>
					<?php echo h($analysisLevels[$event['Event']['analysis']]); ?>
					&nbsp;
				</dd>
				<dt>Distribution</dt>
				<dd>
					<?php echo h($distributionLevels[$event['Event']['distribution']] . ', ' . strtolower(substr(($distributionDescriptions[$event['Event']['distribution']]['formdesc']), 0, 1)) . substr($distributionDescriptions[$event['Event']['distribution']]['formdesc'], 1) . '.'); ?>
					&nbsp;
				</dd>
				<dt>Info</dt>
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
				echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']), array('style' => 'color:red;'));
			} else {
				echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id']));
			}
			?>
			</div></li>
			<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>
	</div>
	<div>
		<h3>Attributes</h3>
		<?php
if (!empty($event['Attribute'])):?>
		<table class="table table-condensed">
		<tr>
			<th>Category</th>
			<th>Type</th>
			<th>Value</th>
			<th>Related Events</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>">IOC</th>
			<th title="<?php echo $attrDescriptions['private']['desc'];?>">Distribution</th>
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
			<td class="showspaces <?php echo $extra; ?>"><?php
			$sigDisplay = $attribute['value'];
			if ('attachment' == $attribute['type'] || 'malware-sample' == $attribute['type'] ) {
				$filenameHash = explode('|', $attribute['value']);
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
				echo $this->Html->link(h($sigDisplay), 'http://www.google.com/search?q=' . h($sigDisplay), array('target' => '_blank'));
			} elseif ('link' == $attribute['type']) {
				echo $this->Html->link(h($sigDisplay), h($sigDisplay));
			} else {
				$sigDisplay = str_replace("\r", '', $sigDisplay);
				echo (h($sigDisplay));
			}
				?></td>
				<td class="<?php echo $extra; ?>" style="max-width:100px;">
				<?php
			$first = 0;
			if (isset($relatedAttributes[$attribute['id']]) && (null != $relatedAttributes[$attribute['id']])) {
				foreach ($relatedAttributes[$attribute['id']] as $relatedAttribute) {
					echo '<span title="'.h($relatedAttribute['info']).'">';
					if ($relatedAttribute['org'] == $me['org']) {
						echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id']), array ('style' => 'color:red;'));
					} else {
						echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id']));
					}

					echo "</span>";
					echo ' ';
				}
			}
				?>&nbsp;
				</td>
				<td class="short <?php echo $extra; ?>"><?php echo $attribute['to_ids'] ? 'Yes' : 'No';?></td>
				<td class="short <?php echo $extra; ?>"><?php echo $attribute['distribution'] != 3 ? $distributionLevels[$attribute['distribution']] : 'All';?></td>
				<td class="short action-links <?php echo $extra;?>">
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
				foreach ($attribute['ShadowAttribute'] as $shadowAttribute):
				?>
				<tr class="highlight2">
					<td class="short highlight2" title="<?php if('' != $shadowAttribute['category']) echo $categoryDefinitions[$shadowAttribute['category']]['desc'];?>">
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
									echo h($sigDisplay);
								}
							}
						?></td>
					<td class="short highlight2">
					</td>
					<td class="short highlight2">
					<?php
						if ($shadowAttribute['to_ids'] != $attribute['to_ids']) echo $shadowAttribute['to_ids'] ? 'Yes' : 'No';
					?></td>
					<td class="short highlight2"></td>
					<td class="short action-links highlight2">
					<?php
						if (($event['Event']['org'] == $me['org'] && $mayPublish) || $isSiteAdmin) {
							echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'accept', $shadowAttribute['id']), array('class' => 'icon-ok', 'title' => 'Accept'));
						}
						echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'discard', $shadowAttribute['id']), array('class' => 'icon-trash', 'title' => 'Discard'));
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
								<td class="showspaces short highlight2"><?php
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
											echo h($sigDisplay);
										}
									?></td>
								<td class="short highlight2">
								</td>
								<td class="short highlight2">
									<?php
										echo $remain['to_ids'] ? 'Yes' : 'No';
									?></td>
									<td class="short highlight2"></td>
									<td class="short action-links highlight2">
									<?php
										if (($event['Event']['org'] == $me['org'] && $mayPublish) || $isSiteAdmin) {
											echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'accept', $remain['id']), array('class' => 'icon-ok', 'title' => 'Accept'));
										}
										echo $this->Html->link('', array('controller' => 'shadow_attributes', 'action' => 'discard',$remain['id']), array('class' => 'icon-trash', 'title' => 'Discard'));
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
</div>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	$("th, td, dt, div, span").tooltip({
		'placement': 'top',
		'container' : 'body',
		delay: { show: 500, hide: 100 }
		});
});
</script>
