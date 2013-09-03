<div class="shadowAttributes index">
	<h2>Proposals</h2>
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


	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th>Event</th>
			<th>
				<?php echo $this->Paginator->sort('org', 'Org');?>
			</th>
			<th>
				Type
			</th>
			<th>
				<?php echo $this->Paginator->sort('id', 'Info');?>
			</th>
		</tr>
		<?php foreach ($shadowAttributes as $event):?>
		<tr>
			<td class="short" onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo h($event['Event']['id']);?>
			</td>
			<td class="short" onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo h($event['ShadowAttribute']['org'])?>
			</td>
			<td class="short" onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php 
					if ($event['ShadowAttribute']['old_id'] != 0) {
						echo 'Attribute edit';
					} else {
						echo 'New Attribute';	
					}
				?>
			</td>
			<td onclick="document.location.href ='/events/view/<?php echo $event['Event']['id'];?>'">
				<?php echo h($event['Event']['info']); ?>
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
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li class="active"><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/attributes/index">List Attributes</a></li>
		<li><a href="/attributes/search">Search Attributes</a></li>
		<li class="divider"></li>
		<li><a href="/events/export">Export</a></li>
		<?php if ($isAclAuth): ?>
		<li><a href="/events/automation">Automation</a></li>
		<?php endif;?>
	</ul>
</div>
