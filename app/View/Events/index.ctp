

<?php if(empty($this->passedArgs['searchinfo'])) $this->passedArgs['searchinfo'] = '';?>
<?php if(empty($this->passedArgs['searchorgc'])) $this->passedArgs['searchorgc'] = '';?>
<?php if(empty($this->passedArgs['searchpublished'])) $this->passedArgs['searchpublished'] = '';?>
<?php //die(debug($events));?>
<div class="events index">
	<?php echo $this->Form->create('', array('action' => 'index')); ?>
	<div class="input-append">
		<div id = "searchinfo">
		<?php
			echo $this->Form->input('searchinfo', array('value' => $this->passedArgs['searchinfo'], 'div' => false, 'label' => 'Value', 'class' => 'input'));
			echo $this->Form->button('Go', array('class' => 'btn', 'div' => false));
		?>
		</div><div id = "searchorgc">
		<?php
			echo $this->Form->input('searchorgc', array('value' => $this->passedArgs['searchorgc'], 'div' => false, 'label' => 'Org'));
			echo $this->Form->button('Go', array('class' => 'btn', 'div' => false));
		?>
		</div><div id = "searchpublished">
		<?php
			echo $this->Form->input('searchpublished', array('options' => array('0' => 'No', '1' => 'Yes'), 'value' => $this->passedArgs['searchpublished'], 'div' => false, 'label' => 'Published'));
			echo $this->Form->button('Go', array('class' => 'btn', 'div' => false));
		?>
		</div>
	</div>

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
	<table><tr>
		<?php
		foreach ($this->passedArgs as $k => $v) {
			if ($v && (substr($k, 0, 6) === 'search')) {
			?>
			<td class="<?php echo (($count < 1) ? 'searchLabelFirst' : 'searchLabel');?>"><?php echo substr($k, 6); ?> : <?php echo $v; ?></td>
			<?php
			$count++;
			}
		}
		if ($count > 0) {
	?>
	<td class="searchLabelCancel"><?php echo $this->Html->link('', array('controller' => 'events', 'action' => 'index'), array('class' => 'icon-remove', 'title' => 'Remove filters'));?></td>
	<?php
	}
	?>
	</tr></table>
	<?php
		echo $this->Form->end();
	?>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th><?php echo $this->Paginator->sort('published', 'Valid.');?></th>
			<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<?php endif; ?>
			<?php if ($isSiteAdmin): ?>
			<th><?php echo $this->Paginator->sort('owner org');?><a href=# onClick='enableField("searchorgc")'><br /><div class="icon-search"></div></a></th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('attribute_count', '#Attr.');?></th>
			<?php if ($isAdmin): ?>
			<th><?php echo $this->Paginator->sort('user_id', 'Email');?></th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('date');?></th>
			<th title="<?php echo $eventDescriptions['risk']['desc'];?>">
				<?php echo $this->Paginator->sort('risk');?>
			</th>
			<th title="<?php echo $eventDescriptions['analysis']['desc'];?>">
				<?php echo $this->Paginator->sort('analysis');?>
			</th>
			<th><?php echo $this->Paginator->sort('info');?><a href=# onClick='enableField("searchinfo")'><br /><div class="icon-search"></div></a></th>
			<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
			<th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
				<?php echo $this->Paginator->sort('distribution');?>
			</th>
			<?php endif; ?>
			<th class="actions"><?php echo __('Actions');?></th>
		</tr>
		<?php foreach ($events as $event):?>
		<tr>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php
				if ($event['Event']['published'] == 1) {
					echo $this->Html->link('', array('controller' => 'events', 'action' => 'view', $event['Event']['id']), array('class' => 'icon-ok', 'title' => 'View'));
				} else {
					echo $this->Html->link('', array('controller' => 'events', 'action' => 'view', $event['Event']['id']), array('class' => 'icon-remove', 'title' => 'View'));
				}?>&nbsp;
			</td>
			<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';"><?php
				$imgRelativePath = 'orgs' . DS . h($event['Event']['orgc']) . '.png';
				$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
				if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Event']['orgc']) . '.png', array('alt' => h($event['Event']['orgc']),'width' => '48','hight' => '48'));
				else echo $this->Html->tag('span', h($event['Event']['orgc']), array('class' => 'welcome', 'style' => 'float:left;'));?><?php
				?>
				&nbsp;
			</td>
			<?php endif;?>
			<?php if ('true' == $isSiteAdmin): ?>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php
				$imgRelativePath = 'orgs' . DS . h($event['Event']['org']) . '.png';
				$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
				if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($event['Event']['org']) . '.png', array('alt' => h($event['Event']['org']),'width' => '48','hight' => '48'));
				else echo $this->Html->tag('span', h($event['Event']['org']), array('class' => 'welcome', 'style' => 'float:left;'));?><?php
				?>&nbsp;
			</td>
			<?php endif; ?>
			<td class="short">
				<?php echo $this->Html->link($event['Event']['id'], array('controller' => 'events', 'action' => 'view', $event['Event']['id'])); ?>&nbsp;
			</td>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php echo $event['Event']['attribute_count']; ?>&nbsp;
			</td>
			<?php if ($isAdmin): ?>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php if($isSiteAdmin || $event['Event']['org'] == $me['org']) echo h($event['User']['email']); ?>&nbsp;
			</td>
			<?php endif; ?>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php echo $event['Event']['date']; ?>&nbsp;
			</td>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php echo $event['Event']['risk']; ?>&nbsp;
			</td>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php echo $analysisLevels[$event['Event']['analysis']]; ?>&nbsp;
			</td>
			<td onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
			</td>
			<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
			<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true);?>';">
				<?php echo $event['Event']['distribution'] != 'All communities' ? $event['Event']['distribution'] : 'All';?>
			</td>
			<?php endif; ?>
			<td class="short action-links">
				<?php
				if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['org'] == $me['org'])))
					echo $this->Form->postLink('', array('action' => 'alert', $event['Event']['id']), array('class' => 'icon-download-alt', 'title' => 'Publish Event'), 'Are you sure this event is complete and everyone should be informed?');
				elseif (0 == $event['Event']['published']) echo 'Not published';

				if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['org'] == $me['org'])) {
					echo $this->Html->link('', array('action' => 'edit', $event['Event']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));
					echo $this->Form->postLink('', array('action' => 'delete', $event['Event']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete # %s?', $event['Event']['id']));
				}
				echo $this->Html->link('', array('controller' => 'events', 'action' => 'view', $event['Event']['id']), array('class' => 'icon-list-alt', 'title' => 'View'));
				?>
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
<div class="actions">
	<ul class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Attributes', array('controller' => 'attributes', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link('Search Attributes', array('controller' => 'attributes', 'action' => 'search')); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Export', array('controller' => 'events', 'action' => 'export')); ?> </li>
		<?php if ($isAclAuth): ?>
		<li><?php echo $this->Html->link('Automation', array('controller' => 'events', 'action' => 'automation')); ?></li>
		<?php endif;?>
	</ul>
</div>
<script>
$(document).ready(disableField('searchinfo'));
$(document).ready(disableField('searchorgc'));
$(document).ready(disableField('searchpublished'));

function disableField(field) {
	document.getElementById(field).style.display="none";
}
function enableField(field) {
	document.getElementById(field).style.display="";
}
</script>