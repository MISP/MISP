<?php if(empty($this->passedArgs['searchinfo'])) $this->passedArgs['searchinfo'] = '';?>
<?php if(empty($this->passedArgs['searchorg'])) $this->passedArgs['searchorg'] = '';?>
<?php if(empty($this->passedArgs['searchDatefrom'])) $this->passedArgs['searchDatefrom'] = '';?>
<?php if(empty($this->passedArgs['searchDateuntil'])) $this->passedArgs['searchDateuntil'] = '';?>
<?php if(empty($this->passedArgs['searchpublished'])) $this->passedArgs['searchpublished'] = '2';?>
<?php if(empty($this->passedArgs['searchtag'])) $this->passedArgs['searchtag'] = '';?>
<div class="events index">
	<h2>Events</h2>
	<div class="pagination">
        <ul>
        <?php
	        $this->Paginator->options(array(
	            'update' => '.span12',
	            'evalScripts' => true,
	            'before' => '$(".progress").show()',
	            'complete' => '$(".progress").hide()',
	        ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
	<?php
	// Let's output a small label of each filter
	$count = 0;
	?>
	<table>
		<tr>
			<?php
			foreach ($this->passedArgs as $k => $v) {
				if ((substr($k, 0, 6) === 'search')) {
					$searchTerm = substr($k, 6);
					if ($searchTerm === 'published') {
						switch ($v) {
							case '0' :
								$value = 'No';
								break;
							case '1' :
								$value = 'Yes';
								break;
							case '2' :
								continue 2;
								break;
						}
	 				} else {
						if (!$v) {
							continue;
						}
						$value = $v;
					}
				?>
				<td class="<?php echo (($count < 1) ? 'searchLabelFirst' : 'searchLabel');?>">
					<?php echo $searchTerm; ?> : <?php echo h($value); ?>
				</td>
				<?php
				$count++;
				}
			}
			if ($count > 0) {
			?>
			<td class="searchLabelCancel">
				<?php echo $this->Html->link('', array('controller' => 'events', 'action' => 'index'), array('class' => 'icon-remove', 'title' => 'Remove filters'));?>
			</td>
			<?php
			}
			?>
		</tr>
	</table>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th class="filter">
				<?php echo $this->Paginator->sort('published');?>
				<a onclick="$('#searchpublished').toggle();" class="icon-search"></a>
				<span id="searchpublished"><br/>
					<?php
					// on change jquery will submit the form
					echo $this->Form->create('', array('action' => 'index', 'style' => 'margin-bottom:0px'));
					echo $this->Form->input('searchorg', array('value' => $this->passedArgs['searchorg'], 'type' => 'hidden'));
					echo $this->Form->input('searchinfo', array('value' => $this->passedArgs['searchinfo'], 'type' => 'hidden'));
					echo $this->Form->input('searchDatefrom', array('value' => $this->passedArgs['searchDatefrom'], 'type' => 'hidden'));
					echo $this->Form->input('searchDateuntil', array('value' => $this->passedArgs['searchDateuntil'], 'type' => 'hidden'));
					echo $this->Form->input('searchtag', array('value' => $this->passedArgs['searchtag'], 'type' => 'hidden'));
					echo $this->Form->input('searchpublished', array(
							'options' => array('0' => 'No', '1' => 'Yes', '2' => 'Any'),
							'default' => 2,
							'label' => '',
							'class' => 'input-mini',
							'onchange' => "$('#EventIndexForm').submit()"
							));
					?>
						<input type="submit" style="visibility:collapse;" />
					<?php
						echo $this->Form->end();
					?>
				</span>
			</th>
			<?php
			if ('true' == Configure::read('MISP.showorg') || $isAdmin) { ?>
			<th class="filter"><?php echo $this->Paginator->sort('org'); ?>
				<a onclick="toggleField('#searchorg')" class="icon-search"></a>
				<span id="searchorg"><br/>
				<?php
				echo $this->Form->create('', array('action' => 'index', 'style' => 'margin-bottom:0px'));
				echo $this->Form->input('searchpublished', array('value' => $this->passedArgs['searchpublished'], 'type' => 'hidden'));
				echo $this->Form->input('searchinfo', array('value' => $this->passedArgs['searchinfo'], 'type' => 'hidden'));
				echo $this->Form->input('searchDatefrom', array('value' => $this->passedArgs['searchDatefrom'], 'type' => 'hidden'));
				echo $this->Form->input('searchDateuntil', array('value' => $this->passedArgs['searchDateuntil'], 'type' => 'hidden'));
				echo $this->Form->input('searchtag', array('value' => $this->passedArgs['searchtag'], 'type' => 'hidden'));
				echo $this->Form->input('searchorg', array(
					'value' => $this->passedArgs['searchorg'],
					'label' => '',
					'class' => 'input-mini'));
				?>
					<input type="submit" style="visibility:collapse;" />
				<?php
					echo $this->Form->end();
				?>
				</span>
			</th>
				<?php
				}
			?>
			<?php if ($isSiteAdmin): ?>
			<th class="filter">
				<?php echo $this->Paginator->sort('owner org');?>
			</th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<?php if (Configure::read('MISP.tagging')): ?>
			<th class="filter">Tags
				<a onclick="toggleField('#searchtag')" class="icon-search"></a>
				<span id="searchtag"><br/>
				<?php
					echo $this->Form->create('', array('action' => 'index', 'style' => 'margin-bottom:0px'));
					echo $this->Form->input('searchorg', array('value' => $this->passedArgs['searchorg'], 'type' => 'hidden'));
					echo $this->Form->input('searchpublished', array('value' => $this->passedArgs['searchpublished'], 'type' => 'hidden'));
					echo $this->Form->input('searchDatefrom', array('value' => $this->passedArgs['searchDatefrom'], 'type' => 'hidden'));
					echo $this->Form->input('searchDateuntil', array('value' => $this->passedArgs['searchDateuntil'], 'type' => 'hidden'));
					echo $this->Form->input('searchinfo', array('value' => $this->passedArgs['searchinfo'], 'type' => 'hidden'));
					echo $this->Form->input('searchtag', array(
							'options' => array($tags),
							'value' => $this->passedArgs['searchtag'],
							'label' => '',
							'onChange' => 'this.form.submit()',
							'class' => 'input-large'));
				?>
					<input type="submit" style="visibility:collapse;" />
				<?php
					echo $this->Form->end();
				?>
				</span>
			</th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('attribute_count', '#Attr.');?></th>
			<?php if ($isSiteAdmin): ?>
			<th><?php echo $this->Paginator->sort('user_id', 'Email');?></th>
			<?php endif; ?>
			<th class="filter">
				<?php echo $this->Paginator->sort('date');?>
				<a onclick="toggleField('#searchdate')" class="icon-search"></a>
				<br/>
				<div id="searchdate" class="input-append input-prepend">
							<?php
							echo $this->Form->create('', array('action' => 'index', 'style' => 'margin-bottom:0px'));
							echo $this->Form->input('searchorg', array('value' => $this->passedArgs['searchorg'], 'type' => 'hidden'));
							echo $this->Form->input('searchinfo', array('value' => $this->passedArgs['searchinfo'], 'type' => 'hidden'));
							echo $this->Form->input('searchpublished', array('value' => $this->passedArgs['searchpublished'], 'type' => 'hidden'));
							echo $this->Form->input('searchtag', array('value' => $this->passedArgs['searchtag'], 'type' => 'hidden'));
							echo $this->Form->input('searchDatefrom', array(
									'value' => $this->passedArgs['searchDatefrom'],
									'label' => false,
									'div' => false,
									'class' => 'span1 datepicker',
									));
							?>
							<input type="submit" class="btn" value="&gt;" style="margin-top:1px;" />
							<?php
							echo $this->Form->input('searchDateuntil', array(
									'value' => $this->passedArgs['searchDateuntil'],
									'label' => false,
									'class' => 'span1 datepicker',
									'div' => false
									));
							?>
								<input type="submit" style="visibility:collapse;" />
							<?php
								echo $this->Form->end();
							?>
				</div>
			</th>
			<th title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>">
				<?php echo $this->Paginator->sort('threat_level_id');?>
			</th>
			<th title="<?php echo $eventDescriptions['analysis']['desc'];?>">
				<?php echo $this->Paginator->sort('analysis');?>
			</th>
			<th class="filter">
				<?php echo $this->Paginator->sort('info');?>
				<a onclick="toggleField('#searchinfo')" class="icon-search"></a>
				<span id="searchinfo"><br/>
				<?php
					echo $this->Form->create('', array('action' => 'index', 'style' => 'margin-bottom:0px'));
					echo $this->Form->input('searchorg', array('value' => $this->passedArgs['searchorg'], 'type' => 'hidden'));
					echo $this->Form->input('searchpublished', array('value' => $this->passedArgs['searchpublished'], 'type' => 'hidden'));
					echo $this->Form->input('searchDatefrom', array('value' => $this->passedArgs['searchDatefrom'], 'type' => 'hidden'));
					echo $this->Form->input('searchDateuntil', array('value' => $this->passedArgs['searchDateuntil'], 'type' => 'hidden'));
					echo $this->Form->input('searchtag', array('value' => $this->passedArgs['searchtag'], 'type' => 'hidden'));
					echo $this->Form->input('searchinfo', array(
							'value' => $this->passedArgs['searchinfo'],
							'label' => '',
							'class' => 'input-large'));
				?>
					<input type="submit" style="visibility:collapse;" />
				<?php
					echo $this->Form->end();
				?>
				</span>
			</th>
			<?php if ('true' == Configure::read('MISP.sync')): ?>
			<th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
				<?php echo $this->Paginator->sort('distribution');?>
			</th>
			<?php endif; ?>
			<th class="actions">Actions</th>

		</tr>
		<?php foreach ($events as $event): ?>
		<tr <?php if($event['Event']['distribution'] == 0) echo 'class = "privateRed"'?>>
			<td class="short" onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php
				if ($event['Event']['published'] == 1) {
				?>
					<a href="/events/view/<?php echo $event['Event']['id'] ?>" class = "icon-ok" title = "View"></a>
				<?php
				} else {
				?>
					<a href="/events/view/<?php echo $event['Event']['id'] ?>" class = "icon-remove" title = "View"></a>
				<?php
				}?>&nbsp;
			</td>
			<?php if ('true' == Configure::read('MISP.showorg') || $isAdmin): ?>
			<td class="short" onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Event']['orgc']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Event']['orgc']) . '.png', array('alt' => h($event['Event']['orgc']), 'title' => h($event['Event']['orgc']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Event']['orgc']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
			<?php endif;?>
			<?php if ('true' == $isSiteAdmin): ?>
			<td class="short" onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php
					$imgRelativePath = 'orgs' . DS . h($event['Event']['org']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Event']['org']) . '.png', array('alt' => h($event['Event']['org']), 'title' => h($event['Event']['org']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($event['Event']['org']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				&nbsp;
			</td>
			<?php endif; ?>
			<td class="short">
				<a href="/events/view/<?php echo $event['Event']['id'] ?>"><?php echo $event['Event']['id'];?></a>
			</td>
			<?php if (Configure::read('MISP.tagging')): ?>
			<td class="short">
				<?php foreach ($event['EventTag'] as $tag):?>
					<span class=tag style="background-color:<?php echo $tag['Tag']['colour']?>" title="<?php echo $tag['Tag']['name']; ?>">&nbsp</span>
				<?php endforeach; ?>
			</td>
			<?php endif; ?>
			<td class="short" onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $event['Event']['attribute_count']; ?>&nbsp;
			</td>
			<?php if ('true' == $isSiteAdmin): ?>
			<td class="short" onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo h($event['User']['email']); ?>&nbsp;
			</td>
			<?php endif; ?>
			<td class="short" onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $event['Event']['date']; ?>&nbsp;
			</td>
			<td class="short" onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php 
				if ($event['ThreatLevel']['name']) echo h($event['ThreatLevel']['name']);
				else echo h($event['Event']['threat_level_id']);
				?>&nbsp;
			</td>
			<td class="short" onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $analysisLevels[$event['Event']['analysis']]; ?>&nbsp;
			</td>
			<td onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
			</td>
			<?php if ('true' == Configure::read('MISP.sync')): ?>
			<td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" onclick="location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : 'All';?>
			</td>
			<?php endif; ?>
			<td class="short action-links">
				<?php
				if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['org'] == $me['org'])))
					echo $this->Form->postLink('', array('action' => 'alert', $event['Event']['id']), array('class' => 'icon-download-alt', 'title' => 'Publish Event'), 'Are you sure this event is complete and everyone should be informed?');
				elseif (0 == $event['Event']['published']) echo 'Not published';

				if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['org'] == $me['org'])) {
				?>
					<a href='/events/view/<?php echo $event['Event']['id'];?>' class = "icon-edit" title = "Edit"></a>
				<?php
					echo $this->Form->postLink('', array('action' => 'delete', $event['Event']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete # %s?', $event['Event']['id']));
				}
				?>
				<a href='/events/view/<?php echo $event['Event']['id'];?>' class = "icon-list-alt" title = "View"></a>
			</td>
		</tr>
		<?php endforeach; ?>
	</table>
	<p>
    <?php
    echo $this->Paginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'index'));
?>

<script type="text/javascript">
$(document).ready( function () {
	// onload hide all buttons
	$('#searchinfo').hide();
	$('#searchorg').hide();
	$('#searchdate').hide();
	$('#searchpublished').hide();
	$('#searchtag').hide();

});

function toggleField(field) {
	$(field).toggle();
	$(field +" input").focus();
}


</script>